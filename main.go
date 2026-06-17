package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	alidns "github.com/alibabacloud-go/alidns-20150109/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	openapiv2 "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	esa "github.com/alibabacloud-go/esa-20240910/v3/client"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/pkg/errors"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&aliDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type aliDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client       *kubernetes.Clientset
	aliDNSClient *alidns.Client
	esaClient    *esa.Client
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type aliDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	AccessToken cmmetav1.SecretKeySelector `json:"accessTokenSecretRef"`
	SecretToken cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	Regionid    string                     `json:"regionId"`
	Service     string                     `json:"service"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *aliDNSProviderSolver) Name() string {
	return "alidns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *aliDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration: %v\n", cfg)

	accessToken, err := c.loadSecretData(cfg.AccessToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	secretKey, err := c.loadSecretData(cfg.SecretToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	switch cfg.service() {
	case "alidns":
		return c.presentAliDNS(cfg, accessToken, secretKey, ch)
	case "esa":
		return c.presentESA(cfg, accessToken, secretKey, ch)
	default:
		return fmt.Errorf("unsupported dns service %q", cfg.Service)
	}
}

func (c *aliDNSProviderSolver) presentAliDNS(cfg aliDNSProviderConfig, accessToken, secretKey []byte, ch *v1alpha1.ChallengeRequest) error {
	client, err := alidns.NewClient(&openapi.Config{
		AccessKeyId:     tea.String(string(accessToken)),
		AccessKeySecret: tea.String(string(secretKey)),
		RegionId:        tea.String(cfg.Regionid),
	})
	if err != nil {
		return err
	}
	c.aliDNSClient = client

	zoneName, err := c.getAliDNSHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: error getting hosted zones: %v", err)
	}

	recordAttributes := c.newAliDNSTxtRecord(zoneName, ch.ResolvedFQDN, ch.Key)

	_, err = c.aliDNSClient.AddDomainRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("alicloud: error adding domain record: %v", err)
	}
	return nil
}

func (c *aliDNSProviderSolver) presentESA(cfg aliDNSProviderConfig, accessToken, secretKey []byte, ch *v1alpha1.ChallengeRequest) error {
	client, err := esa.NewClient(&openapiv2.Config{
		AccessKeyId:     tea.String(string(accessToken)),
		AccessKeySecret: tea.String(string(secretKey)),
		RegionId:        tea.String(cfg.Regionid),
	})
	if err != nil {
		return err
	}
	c.esaClient = client

	siteID, err := c.getESASiteID(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("esa: error getting site id: %v", err)
	}

	_, err = c.esaClient.CreateRecord(&esa.CreateRecordRequest{
		SiteId:     tea.Int64(siteID),
		RecordName: tea.String(util.UnFqdn(ch.ResolvedFQDN)),
		Type:       tea.String("TXT"),
		Ttl:        tea.Int32(1),
		Data: &esa.CreateRecordRequestData{
			Value: tea.String(ch.Key),
		},
	})
	if err != nil {
		return fmt.Errorf("esa: error adding dns record: %v", err)
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *aliDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	accessToken, err := c.loadSecretData(cfg.AccessToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	secretKey, err := c.loadSecretData(cfg.SecretToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	switch cfg.service() {
	case "alidns":
		return c.cleanUpAliDNS(cfg, accessToken, secretKey, ch)
	case "esa":
		return c.cleanUpESA(cfg, accessToken, secretKey, ch)
	default:
		return fmt.Errorf("unsupported dns service %q", cfg.Service)
	}
}

func (c *aliDNSProviderSolver) cleanUpAliDNS(cfg aliDNSProviderConfig, accessToken, secretKey []byte, ch *v1alpha1.ChallengeRequest) error {
	client, err := alidns.NewClient(&openapi.Config{
		AccessKeyId:     tea.String(string(accessToken)),
		AccessKeySecret: tea.String(string(secretKey)),
		RegionId:        tea.String(cfg.Regionid),
	})
	if err != nil {
		return err
	}
	c.aliDNSClient = client

	records, err := c.findAliDNSTxtRecords(ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("alicloud: error finding txt records: %v", err)
	}

	_, err = c.getAliDNSHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	for _, rec := range records {
		if rec != nil && ch.Key == tea.StringValue(rec.Value) {
			request := &alidns.DeleteDomainRecordRequest{
				RecordId: rec.RecordId,
			}
			_, err = c.aliDNSClient.DeleteDomainRecord(request)
			if err != nil {
				return fmt.Errorf("alicloud: error deleting domain record: %v", err)
			}
		}
	}
	return nil
}

func (c *aliDNSProviderSolver) cleanUpESA(cfg aliDNSProviderConfig, accessToken, secretKey []byte, ch *v1alpha1.ChallengeRequest) error {
	client, err := esa.NewClient(&openapiv2.Config{
		AccessKeyId:     tea.String(string(accessToken)),
		AccessKeySecret: tea.String(string(secretKey)),
		RegionId:        tea.String(cfg.Regionid),
	})
	if err != nil {
		return err
	}
	c.esaClient = client

	siteID, err := c.getESASiteID(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("esa: error getting site id: %v", err)
	}

	records, err := c.findESATxtRecords(siteID, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("esa: error finding txt records: %v", err)
	}

	for _, rec := range records {
		if rec == nil || rec.RecordId == nil || rec.Data == nil {
			continue
		}
		if ch.Key != tea.StringValue(rec.Data.Value) {
			continue
		}
		_, err = c.esaClient.DeleteRecord(&esa.DeleteRecordRequest{
			RecordId: rec.RecordId,
		})
		if err != nil {
			return fmt.Errorf("esa: error deleting dns record: %v", err)
		}
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *aliDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (aliDNSProviderConfig, error) {
	cfg := aliDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (cfg aliDNSProviderConfig) service() string {
	if cfg.Service == "" {
		return "alidns"
	}
	return strings.ToLower(cfg.Service)
}

func (c *aliDNSProviderSolver) getAliDNSHostedZone(resolvedZone string) (string, error) {
	request := &alidns.DescribeDomainsRequest{}

	var domains []string
	startPage := int64(1)

	for {
		request.PageNumber = tea.Int64(startPage)

		response, err := c.aliDNSClient.DescribeDomains(request)
		if err != nil {
			return "", fmt.Errorf("alicloud: error describing domains: %v", err)
		}
		if response == nil || response.Body == nil {
			break
		}

		if response.Body.Domains != nil {
			for _, domain := range response.Body.Domains.Domain {
				if domain != nil {
					domains = append(domains, tea.StringValue(domain.DomainName))
				}
			}
		}

		if tea.Int64Value(response.Body.PageNumber)*tea.Int64Value(response.Body.PageSize) >= tea.Int64Value(response.Body.TotalCount) {
			break
		}

		startPage++
	}

	var hostedZone string
	for _, zone := range domains {
		if zone == util.UnFqdn(resolvedZone) {
			hostedZone = zone
		}
	}

	if hostedZone == "" {
		return "", fmt.Errorf("zone %s not found in AliDNS", resolvedZone)
	}
	return hostedZone, nil
}

func (c *aliDNSProviderSolver) newAliDNSTxtRecord(zone, fqdn, value string) *alidns.AddDomainRecordRequest {
	return &alidns.AddDomainRecordRequest{
		Type:       tea.String("TXT"),
		DomainName: tea.String(zone),
		RR:         tea.String(c.extractRecordName(fqdn, zone)),
		Value:      tea.String(value),
	}
}

func (c *aliDNSProviderSolver) findAliDNSTxtRecords(domain string, fqdn string) ([]*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	zoneName, err := c.getAliDNSHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := &alidns.DescribeDomainRecordsRequest{
		DomainName: tea.String(zoneName),
		PageSize:   tea.Int64(500),
		Type:       tea.String("TXT"),
	}

	var records []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord

	result, err := c.aliDNSClient.DescribeDomainRecords(request)
	if err != nil {
		return records, fmt.Errorf("alicloud: error describing domain records: %v", err)
	}
	if result == nil || result.Body == nil || result.Body.DomainRecords == nil {
		return records, nil
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result.Body.DomainRecords.Record {
		if record != nil && tea.StringValue(record.RR) == recordName {
			records = append(records, record)
		}
	}
	return records, nil
}

func (c *aliDNSProviderSolver) findESATxtRecords(siteID int64, fqdn string) ([]*esa.ListRecordsResponseBodyRecords, error) {
	request := &esa.ListRecordsRequest{
		SiteId:          tea.Int64(siteID),
		RecordName:      tea.String(util.UnFqdn(fqdn)),
		RecordMatchType: tea.String("exact"),
		Type:            tea.String("TXT"),
		PageSize:        tea.Int32(500),
	}

	var records []*esa.ListRecordsResponseBodyRecords
	pageNumber := int32(1)
	for {
		request.PageNumber = tea.Int32(pageNumber)

		result, err := c.esaClient.ListRecords(request)
		if err != nil {
			return records, err
		}
		if result == nil || result.Body == nil {
			return records, nil
		}

		records = append(records, result.Body.Records...)

		pageSize := int32(500)
		if result.Body.PageSize != nil {
			pageSize = *result.Body.PageSize
		}
		totalCount := int32(len(records))
		if result.Body.TotalCount != nil {
			totalCount = *result.Body.TotalCount
		}
		if pageNumber*pageSize >= totalCount {
			break
		}
		pageNumber++
	}
	return records, nil
}

func (c *aliDNSProviderSolver) getESASiteID(resolvedZone string) (int64, error) {
	siteName := util.UnFqdn(resolvedZone)
	result, err := c.esaClient.ListSites(&esa.ListSitesRequest{
		SiteName:       tea.String(siteName),
		SiteSearchType: tea.String("exact"),
		PageSize:       tea.Int32(2),
	})
	if err != nil {
		return 0, err
	}
	if result == nil || result.Body == nil || len(result.Body.Sites) == 0 {
		return 0, fmt.Errorf("site %s not found", siteName)
	}
	if len(result.Body.Sites) > 1 || (result.Body.TotalCount != nil && *result.Body.TotalCount > 1) {
		return 0, fmt.Errorf("site %s matched multiple sites", siteName)
	}
	for _, site := range result.Body.Sites {
		if site != nil && site.SiteId != nil {
			return *site.SiteId, nil
		}
	}
	return 0, fmt.Errorf("site %s has no site id", siteName)
}

func (c *aliDNSProviderSolver) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.LastIndex(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (c *aliDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
