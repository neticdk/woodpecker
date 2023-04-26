// Copyright 2022 Woodpecker Authors
// Copyright 2018 Drone.IO Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bitbucketserver

// WARNING! This is an work-in-progress patch and does not yet conform to the coding,
// quality or security standards expected of this project. Please use with caution.

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/mrjones/oauth"
	bb "github.com/neticdk/go-bitbucket/bitbucket"

	"github.com/woodpecker-ci/woodpecker/server/forge"
	"github.com/woodpecker-ci/woodpecker/server/forge/bitbucketserver/internal"
	"github.com/woodpecker-ci/woodpecker/server/forge/common"
	forge_types "github.com/woodpecker-ci/woodpecker/server/forge/types"
	"github.com/woodpecker-ci/woodpecker/server/model"
)

const (
	requestTokenURL   = "%s/plugins/servlet/oauth/request-token"
	authorizeTokenURL = "%s/plugins/servlet/oauth/authorize"
	accessTokenURL    = "%s/plugins/servlet/oauth/access-token"

	secret = "045dfb11b042c3c44d68274fd22338e0" // TODO: Temporary
)

// Opts defines configuration options.
type Opts struct {
	URL               string // Stash server url.
	Username          string // Git machine account username.
	Password          string // Git machine account password.
	ConsumerKey       string // Oauth1 consumer key.
	ConsumerRSA       string // Oauth1 consumer key file.
	ConsumerRSAString string
	SkipVerify        bool // Skip ssl verification.
}

type Config struct {
	URL        string
	Username   string
	Password   string
	SkipVerify bool
	Consumer   *oauth.Consumer
}

// New returns a Forge implementation that integrates with Bitbucket Server,
// the on-premise edition of Bitbucket Cloud, formerly known as Stash.
func New(opts Opts) (forge.Forge, error) {
	config := &Config{
		URL:        opts.URL,
		Username:   opts.Username,
		Password:   opts.Password,
		SkipVerify: opts.SkipVerify,
	}

	switch {
	case opts.Username == "":
		return nil, fmt.Errorf("Must have a git machine account username")
	case opts.Password == "":
		return nil, fmt.Errorf("Must have a git machine account password")
	case opts.ConsumerKey == "":
		return nil, fmt.Errorf("Must have a oauth1 consumer key")
	}

	if opts.ConsumerRSA == "" && opts.ConsumerRSAString == "" {
		return nil, fmt.Errorf("must have CONSUMER_RSA_KEY set to the path of a oauth1 consumer key file or CONSUMER_RSA_KEY_STRING set to the value of a oauth1 consumer key")
	}

	var keyFileBytes []byte
	if opts.ConsumerRSA != "" {
		var err error
		keyFileBytes, err = os.ReadFile(opts.ConsumerRSA)
		if err != nil {
			return nil, err
		}
	} else {
		keyFileBytes = []byte(opts.ConsumerRSAString)
	}

	block, _ := pem.Decode(keyFileBytes)
	PrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	config.Consumer = CreateConsumer(opts.URL, opts.ConsumerKey, PrivateKey)
	return config, nil
}

// Name returns the string name of this driver
func (c *Config) Name() string {
	return "stash"
}

func (c *Config) Login(ctx context.Context, res http.ResponseWriter, req *http.Request) (*model.User, error) {
	requestToken, u, err := c.Consumer.GetRequestTokenAndUrl("oob")
	if err != nil {
		return nil, err
	}
	code := req.FormValue("oauth_verifier")
	if len(code) == 0 {
		http.Redirect(res, req, u, http.StatusSeeOther)
		return nil, nil
	}
	requestToken.Token = req.FormValue("oauth_token")
	accessToken, err := c.Consumer.AuthorizeToken(requestToken, code)
	if err != nil {
		return nil, err
	}

	client := internal.NewClientWithToken(ctx, c.URL, c.Consumer, accessToken.Token)

	user, err := client.FindCurrentUser()
	if err != nil {
		return nil, err
	}

	return convertUser(user, accessToken), nil
}

// Auth is not supported by the Stash driver.
func (*Config) Auth(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("Not Implemented")
}

// Teams is not supported by the Stash driver.
func (*Config) Teams(_ context.Context, _ *model.User) ([]*model.Team, error) {
	var teams []*model.Team
	return teams, nil
}

// TeamPerm is not supported by the Stash driver.
func (*Config) TeamPerm(_ *model.User, _ string) (*model.Perm, error) {
	return nil, nil
}

func (c *Config) Repo(ctx context.Context, u *model.User, _ model.ForgeRemoteID, owner, name string) (*model.Repo, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	r, _, err := bc.Projects.GetRepository(ctx, owner, name)
	if err != nil {
		return nil, fmt.Errorf("unable to get repository: %w", err)
	}

	b, _, err := bc.Projects.GetDefaultBranch(ctx, owner, name)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch default branch: %w", err)
	}

	perms := &model.Perm{Pull: true}
	_, _, err = bc.Projects.ListWebhooks(ctx, owner, name, &bb.ListOptions{})
	if err == nil {
		perms.Push = true
		perms.Admin = true
	}

	return convertRepo(r, perms, b.DisplayID), nil
}

func (c *Config) Repos(ctx context.Context, u *model.User) ([]*model.Repo, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	opts := &bb.RepositorySearchOptions{Permission: bb.PermissionRepoAdmin}
	var all []*model.Repo
	for {
		repos, resp, err := bc.Projects.SearchRepositories(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("unable to search repositories: %w", err)
		}
		for _, r := range repos {
			perms := &model.Perm{Pull: true, Push: true, Admin: true}
			all = append(all, convertRepo(r, perms, ""))
		}
		if resp.LastPage {
			break
		}
		opts.Start = resp.NextPageStart
	}

	return all, nil
}

func (c *Config) File(ctx context.Context, u *model.User, r *model.Repo, p *model.Pipeline, f string) ([]byte, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	b, _, err := bc.Projects.GetTextFileContent(ctx, r.Owner, r.Name, f, p.Ref)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *Config) Dir(ctx context.Context, u *model.User, r *model.Repo, p *model.Pipeline, path string) ([]*forge_types.FileMeta, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	opts := &bb.FilesListOptions{}
	var all []*forge_types.FileMeta
	for {
		list, resp, err := bc.Projects.ListFiles(ctx, r.Owner, r.Name, path, opts)
		if err != nil {
			return nil, err
		}
		for _, f := range list {
			data, err := c.File(ctx, u, r, p, f)
			if err != nil {
				return nil, err
			}
			all = append(all, &forge_types.FileMeta{Name: f, Data: data})
		}
		if resp.LastPage {
			break
		}
		opts.Start = resp.NextPageStart
	}
	return all, nil
}

func (c *Config) Status(ctx context.Context, u *model.User, repo *model.Repo, pipeline *model.Pipeline, step *model.Step) error {
	bc, err := c.newClient(u)
	if err != nil {
		return fmt.Errorf("unable to create bitbucket client: %w", err)
	}
	status := &bb.BuildStatus{
		State:       convertStatus(pipeline.Status),
		URL:         common.GetPipelineStatusLink(repo, pipeline, step),
		Key:         common.GetPipelineStatusContext(repo, pipeline, step),
		Description: common.GetPipelineStatusDescription(pipeline.Status),
	}
	_, err = bc.Projects.CreateBuildStatus(ctx, repo.Owner, repo.Name, pipeline.Commit, status)
	return err
}

func (c *Config) Netrc(_ *model.User, r *model.Repo) (*model.Netrc, error) {
	host, err := common.ExtractHostFromCloneURL(r.Clone)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	return &model.Netrc{
		Login:    c.Username,
		Password: c.Password,
		Machine:  host,
	}, nil
}

func (c *Config) Activate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	bc, err := c.newClient(u)
	if err != nil {
		return fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	err = c.Deactivate(ctx, u, r, link)
	if err != nil {
		return fmt.Errorf("unable to deactive old webhooks: %w", err)
	}

	lu, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("unable to parse webhook link [%s]: %w", link, err)
	}
	lu.RawQuery = "" // Remove the access token part here - we use the secret seed to validate integrity

	webhook := &bb.Webhook{
		Name:   "Woodpecker",
		URL:    lu.String(),
		Events: []bb.EventKey{bb.EventKeyRepoRefsChanged, bb.EventKeyPullRequestFrom},
		Active: true,
		Config: &bb.WebhookConfiguration{
			Secret: secret,
		},
	}
	_, _, err = bc.Projects.CreateWebhook(ctx, r.Owner, r.Name, webhook)
	return err
}

// Branches returns the names of all branches for the named repository.
func (c *Config) Branches(ctx context.Context, u *model.User, r *model.Repo) ([]string, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return nil, fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	opts := &bb.BranchSearchOptions{}
	var all []string
	for {
		branches, resp, err := bc.Projects.SearchBranches(ctx, r.Owner, r.Name, opts)
		if err != nil {
			return nil, err
		}
		for _, b := range branches {
			all = append(all, b.DisplayID)
		}
		if resp.LastPage {
			break
		}
		opts.Start = resp.NextPageStart
	}

	return all, nil
}

func (c *Config) BranchHead(ctx context.Context, u *model.User, r *model.Repo, b string) (string, error) {
	bc, err := c.newClient(u)
	if err != nil {
		return "", fmt.Errorf("unable to create bitbucket client: %w", err)
	}
	branches, _, err := bc.Projects.SearchBranches(ctx, r.Owner, r.Name, &bb.BranchSearchOptions{Filter: b})
	if err != nil {
		return "", err
	}
	if len(branches) == 0 {
		return "", fmt.Errorf("no matching branches returned")
	}
	for _, branch := range branches {
		if branch.DisplayID == b {
			return branch.LatestCommit, nil
		}
	}
	return "", fmt.Errorf("no matching branches found")
}

func (c *Config) PullRequests(_ context.Context, _ *model.User, _ *model.Repo, _ *model.PaginationData) ([]*model.PullRequest, error) {
	/*
		bc, err := c.newClient(u)
		if err != nil {
			return nil, err
		}
	*/
	return nil, forge_types.ErrNotImplemented
}

func (c *Config) Deactivate(ctx context.Context, u *model.User, r *model.Repo, link string) error {
	bc, err := c.newClient(u)
	if err != nil {
		return fmt.Errorf("unable to create bitbucket client: %w", err)
	}

	lu, err := url.Parse(link)
	if err != nil {
		return err
	}

	opts := &bb.ListOptions{}
	var ids []uint64
	for {
		hooks, resp, err := bc.Projects.ListWebhooks(ctx, r.Owner, r.Name, opts)
		if err != nil {
			return err
		}
		for _, h := range hooks {
			hu, err := url.Parse(h.URL)
			if err == nil && hu.Host == lu.Host {
				ids = append(ids, h.ID)
			}
		}
		if resp.LastPage {
			break
		}
		opts.Start = resp.NextPageStart
	}

	for _, id := range ids {
		_, err = bc.Projects.DeleteWebhook(ctx, r.Owner, r.Name, id)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) Hook(_ context.Context, r *http.Request) (*model.Repo, *model.Pipeline, error) {
	ev, err := bb.ParsePayload(r, []byte(secret))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse payload from webhook invocation: %w", err)
	}

	switch e := ev.(type) {
	case *bb.RepositoryPushEvent:
		repo := convertRepo(&e.Repository, &model.Perm{}, "")
		pipe := convertRepositoryPushEvent(e, c.URL)
		return repo, pipe, nil
	case *bb.PullRequestEvent:
		repo := convertRepo(&e.PullRequest.Source.Repository, &model.Perm{}, "")
		pipe := convertPullRequestEvent(e, c.URL)
		return repo, pipe, nil
	}

	return nil, nil, fmt.Errorf("unable to handle event")
}

// OrgMembership returns if user is member of organization and if user
// is admin/owner in this organization.
func (c *Config) OrgMembership(_ context.Context, _ *model.User, _ string) (*model.OrgPerm, error) {
	// TODO: Not implemented currently
	return nil, nil
}

func (c *Config) newClient(u *model.User) (*bb.Client, error) {
	token := &oauth.AccessToken{
		Token: u.Token,
	}
	cl, err := c.Consumer.MakeHttpClient(token)
	if err != nil {
		return nil, err
	}
	return bb.NewClient(fmt.Sprintf("%s/rest", c.URL), cl)
}

func CreateConsumer(URL, ConsumerKey string, PrivateKey *rsa.PrivateKey) *oauth.Consumer {
	consumer := oauth.NewRSAConsumer(
		ConsumerKey,
		PrivateKey,
		oauth.ServiceProvider{
			RequestTokenUrl:   fmt.Sprintf(requestTokenURL, URL),
			AuthorizeTokenUrl: fmt.Sprintf(authorizeTokenURL, URL),
			AccessTokenUrl:    fmt.Sprintf(accessTokenURL, URL),
			HttpMethod:        "POST",
		})
	consumer.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
	}
	return consumer
}
