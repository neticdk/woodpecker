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

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mrjones/oauth"
	bb "github.com/neticdk/go-bitbucket/bitbucket"

	"github.com/woodpecker-ci/woodpecker/server/forge/bitbucketserver/internal"
	"github.com/woodpecker-ci/woodpecker/server/model"
)

func convertStatus(status model.StatusValue) bb.BuildStatusState {
	switch status {
	case model.StatusPending, model.StatusRunning:
		return bb.BuildStatusStateInProgress
	case model.StatusSuccess:
		return bb.BuildStatusStateSuccessful
	default:
		return bb.BuildStatusStateFailed
	}
}

func convertRepo(from *bb.Repository) *model.Repo {
	r := &model.Repo{
		ForgeRemoteID: model.ForgeRemoteID(fmt.Sprintf("%d", from.ID)),
		Name:          from.Slug,
		Owner:         from.Project.Key,
		Branch:        "master",
		SCMKind:       model.RepoGit,
		IsSCMPrivate:  true, // Since we have to use Netrc it has to always be private :/ TODO: Is this really true?
		FullName:      from.Name,
		Perm: &model.Perm{
			Push: true,
			Pull: true,
		},
	}

	for _, l := range from.Links["clone"] {
		if l.Name == "http" {
			r.Clone = l.Href
		}
	}

	if l, ok := from.Links["self"]; ok && len(l) > 0 {
		r.Link = l[0].Href
	}

	return r
}

func convertRepositoryPushEvent(ev bb.RepositoryPushEvent, baseURL string) *model.Pipeline {
	authorLabel := ev.ToCommit.Author.Name
	if len(authorLabel) > 40 {
		authorLabel = authorLabel[0:37] + "..."
	}
	pipeline := &model.Pipeline{
		Commit:    ev.ToCommit.ID,
		Branch:    ev.Changes[0].Ref.DisplayID,
		Message:   ev.ToCommit.Message,
		Avatar:    avatarLink(ev.ToCommit.Author.Email),
		Author:    authorLabel,
		Email:     ev.ToCommit.Author.Email,
		Timestamp: time.Time(ev.Date).UTC().Unix(),
		Ref:       ev.Changes[0].RefId,
		Link:      fmt.Sprintf("%s/projects/%s/repos/%s/commits/%s", baseURL, ev.Repository.Project.Key, ev.Repository.Slug, ev.ToCommit.ID),
	}
	return pipeline
}

func convertPullRequestEvent(ev bb.PullRequestEvent, baseURL string) *model.Pipeline {
	authorLabel := ev.Actor.Name
	if len(authorLabel) > 40 {
		authorLabel = authorLabel[0:37] + "..."
	}
	pipeline := &model.Pipeline{
		Commit:    ev.PullRequest.Source.Latest,
		Branch:    ev.PullRequest.Source.DisplayID,
		Message:   "PR",
		Avatar:    avatarLink(ev.Actor.Email),
		Author:    authorLabel,
		Email:     ev.Actor.Email,
		Timestamp: time.Time(ev.Date).UTC().Unix(),
		Ref:       ev.PullRequest.Source.ID,
		Link:      fmt.Sprintf("%s/projects/%s/repos/%s/commits/%s", baseURL, ev.PullRequest.Source.Repository.Project.Key, ev.PullRequest.Source.Repository.Slug, ev.PullRequest.Source.Latest),
	}
	return pipeline
}

// convertPushHookLegacy is a helper function used to convert a Bitbucket push
// hook to the Woodpecker pipeline struct holding commit information.
func convertPushHookLegacy(hook *internal.PostHook, baseURL string) *model.Pipeline {
	branch := strings.TrimPrefix(
		strings.TrimPrefix(
			hook.RefChanges[0].RefID,
			"refs/heads/",
		),
		"refs/tags/",
	)

	// Ensuring the author label is not longer then 40 for the label of the commit author (default size in the db)
	authorLabel := hook.Changesets.Values[0].ToCommit.Author.Name
	if len(authorLabel) > 40 {
		authorLabel = authorLabel[0:37] + "..."
	}

	pipeline := &model.Pipeline{
		Commit:    hook.RefChanges[0].ToHash, // TODO check for index value
		Branch:    branch,
		Message:   hook.Changesets.Values[0].ToCommit.Message, // TODO check for index Values
		Avatar:    avatarLink(hook.Changesets.Values[0].ToCommit.Author.EmailAddress),
		Author:    authorLabel,
		Email:     hook.Changesets.Values[0].ToCommit.Author.EmailAddress,
		Timestamp: time.Now().UTC().Unix(),
		Ref:       hook.RefChanges[0].RefID, // TODO check for index Values
		Link:      fmt.Sprintf("%s/projects/%s/repos/%s/commits/%s", baseURL, hook.Repository.Project.Key, hook.Repository.Slug, hook.RefChanges[0].ToHash),
	}
	if strings.HasPrefix(hook.RefChanges[0].RefID, "refs/tags/") {
		pipeline.Event = model.EventTag
	} else {
		pipeline.Event = model.EventPush
	}

	return pipeline
}

// convertUser is a helper function used to convert a Bitbucket user account
// structure to the Woodpecker User structure.
func convertUser(from *internal.User, token *oauth.AccessToken) *model.User {
	return &model.User{
		Login:  from.Slug,
		Token:  token.Token,
		Email:  from.EmailAddress,
		Avatar: avatarLink(from.EmailAddress),
	}
}

func avatarLink(email string) string {
	hasher := md5.New()
	hasher.Write([]byte(strings.ToLower(email)))
	emailHash := fmt.Sprintf("%v", hex.EncodeToString(hasher.Sum(nil)))
	avatarURL := fmt.Sprintf("https://www.gravatar.com/avatar/%s.jpg", emailHash)
	return avatarURL
}
