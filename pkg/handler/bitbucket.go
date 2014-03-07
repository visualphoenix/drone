package handler

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/drone/drone/pkg/build/script"
	"github.com/drone/drone/pkg/database"
	. "github.com/drone/drone/pkg/model"
	"github.com/drone/drone/pkg/queue"
	"github.com/drone/go-bitbucket/bitbucket"
	"github.com/drone/go-bitbucket/oauth1"

	//"launchpad.net/goyaml"
)

type BitbucketHandler struct {
	queue *queue.Queue
}

func NewBitbucketHandler(queue *queue.Queue) *BitbucketHandler {
	return &BitbucketHandler{
		queue: queue,
	}
}

func (b *BitbucketHandler) Link(w http.ResponseWriter, r *http.Request, u *User) error {
	// get settings from database
	settings := database.SettingsMust()

	// bitbucket oauth1 consumer
	var consumer = oauth1.Consumer{
		RequestTokenURL:  "https://bitbucket.org/api/1.0/oauth/request_token/",
		AuthorizationURL: "https://bitbucket.org/!api/1.0/oauth/authenticate",
		AccessTokenURL:   "https://bitbucket.org/api/1.0/oauth/access_token/",
		CallbackURL:      settings.URL().String() + "/auth/login/bitbucket",
		ConsumerKey:      settings.BitbucketKey,
		ConsumerSecret:   settings.BitbucketSecret,
	}

	// get the oauth verifier
	verifier := r.FormValue("oauth_verifier")
	if len(verifier) == 0 {
		// Generate a Request Token
		requestToken, err := consumer.RequestToken()
		if err != nil {
			return err
		}

		// add the request token as a signed cookie
		SetCookie(w, r, "bitbucket_token", requestToken.Encode())

		url, _ := consumer.AuthorizeRedirect(requestToken)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return nil
	}

	// remove bitbucket token data once before redirecting
	// back to the application.
	defer DelCookie(w, r, "bitbucket_token")

	// get the tokens from the request
	requestTokenStr := GetCookie(r, "bitbucket_token")
	requestToken, err := oauth1.ParseRequestTokenStr(requestTokenStr)
	if err != nil {
		return err
	}

	// exchange for an access token
	accessToken, err := consumer.AuthorizeToken(requestToken, verifier)
	if err != nil {
		return err
	}

	// create the Bitbucket client
	client := bitbucket.New(
		settings.BitbucketKey,
		settings.BitbucketSecret,
		u.BitbucketToken,
		u.BitbucketSecret,
	)

	// get the currently authenticated Bitbucket User
	user, err := client.Users.Current()
	if err != nil {
		return err
	}

	// update the user account
	u.BitbucketLogin = user.User.Username
	u.BitbucketToken = accessToken.Token()
	u.BitbucketSecret = accessToken.Secret()
	if err := database.SaveUser(u); err != nil {
		return err
	}

	http.Redirect(w, r, "/new/bitbucket.org", http.StatusSeeOther)
	return nil
}

// Returns an HTML form to add a new Bitbucket repository to Drone.
func (b *BitbucketHandler) Add(w http.ResponseWriter, r *http.Request, u *User) error {
	settings := database.SettingsMust()
	teams, err := database.ListTeams(u.ID)
	if err != nil {
		return err
	}
	data := struct {
		User     *User
		Teams    []*Team
		Settings *Settings
	}{u, teams, settings}
	// if the user hasn't linked their Bitbucket account
	// render a different template
	if len(u.BitbucketToken) == 0 {
		return RenderTemplate(w, "bitbucket_link.html", &data)
	}
	// otherwise display the template for adding
	// a new Bitbucket repository.
	return RenderTemplate(w, "bitbucket_add.html", &data)
}

//
func (b *BitbucketHandler) Create(w http.ResponseWriter, r *http.Request, u *User) error {
	teamName := r.FormValue("team")
	owner := r.FormValue("owner")
	name := r.FormValue("name")

	// get the github settings from the database
	settings := database.SettingsMust()

	// create the Bitbucket client
	client := bitbucket.New(
		settings.BitbucketKey,
		settings.BitbucketSecret,
		u.BitbucketToken,
		u.BitbucketSecret,
	)

	bitbucketRepo, err := client.Repos.Find(owner, name)
	if err != nil {
		return err
	}

	repo, err := NewGitHubRepo(settings.GitHubDomain, owner, name, bitbucketRepo.Private)
	if err != nil {
		return err
	}

	repo.UserID = u.ID
	repo.Private = bitbucketRepo.Private

	// if the user chose to assign to a team account
	// we need to retrieve the team, verify the user
	// has access, and then set the team id.
	if len(teamName) > 0 {
		team, err := database.GetTeamSlug(teamName)
		if err != nil {
			log.Printf("error retrieving team %s", teamName)
			return err
		}

		// user must be an admin member of the team
		if ok, _ := database.IsMemberAdmin(u.ID, team.ID); !ok {
			return fmt.Errorf("Forbidden")
		}

		repo.TeamID = team.ID
	}

	// if the repository is private we'll need
	// to upload a github key to the repository
	if repo.Private {
		// name the key
		keyName := fmt.Sprintf("%s@%s", repo.Owner, settings.Domain)

		// create the github key, or update if one already exists
		_, err := client.RepoKeys.CreateUpdate(owner, name, repo.PublicKey, keyName)
		if err != nil {
			return fmt.Errorf("Unable to add Public Key to your GitHub repository")
		}
	} else {

	}

	// create a hook so that we get notified when code
	// is pushed to the repository and can execute a build.
	link := fmt.Sprintf("%s://%s/hook/bitbucket.org?id=%s", settings.Scheme, settings.Domain, repo.Slug)

	// add the hook
	if _, err := client.Brokers.CreateUpdate(owner, name, link, bitbucket.BrokerTypePost); err != nil {
		return fmt.Errorf("Unable to add Hook to your GitHub repository. %s", err.Error())
	}

	// Save to the database
	if err := database.SaveRepo(repo); err != nil {
		log.Print("error saving new repository to the database")
		return err
	}

	return RenderText(w, http.StatusText(http.StatusOK), http.StatusOK)
}

// Processes a Bitbucket Pull Request hook
func (b *BitbucketHandler) Hook(w http.ResponseWriter, r *http.Request, u *User) error {
	// get the payload from the request
	payload := r.FormValue("payload")

	// parse the post-commit hook
	hook, err := bitbucket.ParseHook([]byte(payload))
	if err != nil {
		return err
	}

	// get the repo from the URL
	repoId := r.FormValue("id")

	// get the repo from the database, return error if not found
	repo, err := database.GetRepoSlug(repoId)
	if err != nil {
		return RenderText(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}

	// Get the user that owns the repository
	user, err := database.GetUser(repo.UserID)
	if err != nil {
		return RenderText(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	// Verify that the commit doesn't already exist.
	// We should never build the same commit twice.
	_, err = database.GetCommitHash(hook.Commits[len(hook.Commits)-1].Hash, repo.ID)
	if err != nil && err != sql.ErrNoRows {
		return RenderText(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}

	commit := &Commit{}
	commit.RepoID = repo.ID
	commit.Branch = hook.Commits[len(hook.Commits)-1].Branch
	commit.Hash = hook.Commits[len(hook.Commits)-1].Hash
	commit.Status = "Pending"
	commit.Created = time.Now().UTC()
	commit.Message = hook.Commits[len(hook.Commits)-1].Message
	commit.Timestamp = time.Now().UTC().String()
	commit.SetAuthor(hook.Commits[len(hook.Commits)-1].Author)

	// get the github settings from the database
	settings := database.SettingsMust()

	// create the Bitbucket client
	client := bitbucket.New(
		settings.BitbucketKey,
		settings.BitbucketSecret,
		user.BitbucketToken,
		user.BitbucketSecret,
	)

	// get the yaml from the database
	raw, err := client.Sources.Find(repo.Owner, repo.Name, commit.Hash, ".drone.yml")
	if err != nil {
		return RenderText(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}

	// parse the build script
	buildscript, err := script.ParseBuild([]byte(raw.Data), repo.Params)
	if err != nil {
		msg := "Could not parse your .drone.yml file.  It needs to be a valid drone yaml file.\n\n" + err.Error() + "\n"
		if err := saveFailedBuild(commit, msg); err != nil {
			return RenderText(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return RenderText(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	// save the commit to the database
	if err := database.SaveCommit(commit); err != nil {
		return RenderText(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	// save the build to the database
	build := &Build{}
	build.Slug = "1" // TODO
	build.CommitID = commit.ID
	build.Created = time.Now().UTC()
	build.Status = "Pending"
	if err := database.SaveBuild(build); err != nil {
		return RenderText(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	// send the build to the queue
	b.queue.Add(&queue.BuildTask{Repo: repo, Commit: commit, Build: build, Script: buildscript})

	// OK!
	return RenderText(w, http.StatusText(http.StatusOK), http.StatusOK)
}
