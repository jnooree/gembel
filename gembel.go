package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

var (
	ghClient *github.Client
	ghCtx    context.Context

	reHex = regexp.MustCompile("^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

	version = "master"
	commit  = "none"
	date    = "unknown"
)

type Label struct {
	Name        string
	Color       string
	Description *string
	Replace     *string
}

func (l *Label) to_github() (gl *github.Label) {
	return &github.Label{
		Name:        &l.Name,
		Color:       &l.Color,
		Description: l.Description,
	}
}

type Repo struct {
	Owner string
	Name  string
}

func (r Repo) String() string {
	return fmt.Sprintf("%s/%s", r.Owner, r.Name)
}

type RawConfig struct {
	Labels       []Label
	Deletes      []string
	Repositories []string
	Strict       bool
}

type ParsedConfig struct {
	Labels  []Label
	Deletes []string
	Repos   []Repo
	Strict  bool
}

func (rc *RawConfig) parse() (pc ParsedConfig, e error) {
	if len(rc.Labels) == 0 && len(rc.Deletes) == 0 {
		return pc, errors.New("empty labels and deletes in config file")
	}
	if len(rc.Repositories) == 0 {
		return pc, errors.New("empty target repositories in config file")
	}

	m := make(map[string]bool)

	for i, label := range rc.Labels {
		if label.Name == "" {
			return pc, errors.New("label name can not be empty")
		}

		label.Color = strings.TrimPrefix(label.Color, "#")
		if !reHex.MatchString(label.Color) {
			return pc, errors.New("label color must be in 6 character hex code")
		}

		if _, ok := m[label.Name]; ok {
			return pc, fmt.Errorf("%s in `replaces` is used more than once", label.Name)
		}

		rc.Labels[i] = label
	}

	pc.Labels = rc.Labels
	pc.Deletes = rc.Deletes
	pc.Repos = make([]Repo, len(rc.Repositories))
	pc.Strict = rc.Strict

	for i, repo := range rc.Repositories {
		parts := strings.Split(repo, "/")
		if len(parts) != 2 {
			return pc, fmt.Errorf("invalid repo format %s, shoud be user/repo", repo)
		}
		if parts[0] == "" || parts[1] == "" {
			return pc, fmt.Errorf("invalid repo format %s, shoud be user/repo", repo)
		}

		pc.Repos[i] = Repo{
			Owner: parts[0],
			Name:  parts[1],
		}
	}

	return pc, nil
}

type Action int

const (
	Create Action = iota
	Update
	Delete
	Skip
)

type Result struct {
	Action Action
	From   *github.Label
	To     *Label
	Error  error
}

func (r *Result) String() (ret string) {
	prefix := "[ OK ]"
	if r.Error != nil {
		prefix = "[FAIL]"
	}

	switch r.Action {
	case Update:
		ret = fmt.Sprintf("%s Updated label named '%s' with color '%s' to '%s' with color '%s'", prefix, r.From.GetName(), r.From.GetColor(), r.To.Name, r.To.Color)
	case Create:
		ret = fmt.Sprintf("%s Created label named '%s' with color '%s'", prefix, r.To.Name, r.To.Color)
	case Delete:
		ret = fmt.Sprintf("%s Deleted label named '%s'", prefix, r.From.GetName())
	case Skip:
		ret = fmt.Sprintf("[SKIP] Skipped matching label named '%s'", r.To.Name)
	}

	return ret
}

func main() {
	if len(os.Args) < 2 {
		usage(errors.New("missing config file"))
	}
	if os.Getenv("GITHUB_TOKEN") == "" {
		usage(errors.New("empty GITHUB_TOKEN in env"))
	}
	c, err := ReadConfig(os.Args[1])
	if err != nil {
		usage(err)
	}

	run(&c)
}

func ReadConfig(path string) (c ParsedConfig, err error) {
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()

	fc, err := ioutil.ReadAll(f)
	if err != nil {
		return c, err
	}

	rc := RawConfig{}
	if err = json.Unmarshal(fc, &rc); err != nil {
		return c, fmt.Errorf("json unmarshal error: %s", err)
	}

	return rc.parse()
}

func run(c *ParsedConfig) {
	ghCtx = context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ghCtx, ts)
	ghClient = github.NewClient(tc)

	for _, repo := range c.Repos {
		fmt.Printf("Update labels in repo %s...\n", repo)

		results, err := UpdateRepo(&repo, c)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}

		printResults(results)
	}
}

func printResults(results []Result) {
	for _, result := range results {
		fmt.Printf("* %s\n", &result)
	}
	fmt.Println("")
}

func UpdateRepo(repo *Repo, pc *ParsedConfig) (results []Result, err error) {
	// First, get all labels, mapped to their colors, from the repoOwner.
	repoLabels, err := GetRepoLabels(repo)
	if err != nil {
		return results, err
	}

	// Foreach labels from config:
	// - If label name exists in current labels, perform update. Probably
	//   the color changes.
	// - If label replace found in repoLabels, perform update.
	// - If no match create new label.
	var result Result

	for i, label := range pc.Labels {
		ref, ok := repoLabels[label.Name]
		skip := false

		if ok {
			skip = label.Color == ref.GetColor() && (label.Description == nil || *label.Description == ref.GetDescription())
		} else if label.Replace != nil {
			ref, ok = repoLabels[*label.Replace]
		}

		if skip {
			result = Result{
				Action: Skip,
				From:   ref,
				To:     &pc.Labels[i],
				Error:  nil,
			}
		} else if ok {
			result = Result{
				Action: Update,
				From:   ref,
				To:     &pc.Labels[i],
				Error:  UpdateLabel(repo, ref.Name, &label),
			}
		} else {
			result = Result{
				Action: Create,
				From:   nil,
				To:     &pc.Labels[i],
				Error:  CreateLabel(repo, &label),
			}
		}

		results = append(results, result)
	}

	for _, name := range pc.Deletes {
		ref, ok := repoLabels[name]

		var err error
		if !ok {
			ref = new(github.Label)
			ref.Name = &name

			err = fmt.Errorf("%s not fount", name)
		} else {
			err = DeleteLabel(repo, &name)
		}

		result = Result{
			Action: Delete,
			From:   ref,
			To:     nil,
			Error:  err,
		}

		results = append(results, result)
	}

	if pc.Strict {
		m := make(map[string]bool, len(pc.Labels))
		for _, label := range pc.Labels {
			m[label.Name] = true
		}

		repoLabels, err = GetRepoLabels(repo)
		if err != nil {
			return results, err
		}

		for name, ref := range repoLabels {
			if _, ok := m[name]; !ok {
				result = Result{
					Action: Delete,
					From:   ref,
					To:     nil,
					Error:  DeleteLabel(repo, &name),
				}

				results = append(results, result)
			}
		}
	}

	return results, nil
}

func UpdateLabel(repo *Repo, labelName *string, label *Label) error {
	if _, _, err := ghClient.Issues.EditLabel(ghCtx, repo.Owner, repo.Name, *labelName, label.to_github()); err != nil {
		return err
	}

	return nil
}

func CreateLabel(repo *Repo, label *Label) error {
	if _, _, err := ghClient.Issues.CreateLabel(ghCtx, repo.Owner, repo.Name, label.to_github()); err != nil {
		return err
	}

	return nil
}

func DeleteLabel(repo *Repo, labelName *string) error {
	if _, err := ghClient.Issues.DeleteLabel(ghCtx, repo.Owner, repo.Name, *labelName); err != nil {
		return err
	}

	return nil
}

func GetRepoLabels(repo *Repo) (m map[string]*github.Label, err error) {
	opt := &github.ListOptions{
		PerPage: 100,
	}

	m = make(map[string]*github.Label)
	for {
		repoLabels, resp, err := ghClient.Issues.ListLabels(ghCtx, repo.Owner, repo.Name, opt)
		if err != nil {
			return m, err
		}
		for _, label := range repoLabels {
			m[label.GetName()] = label
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return m, err
}

func getVersion() string {
	return fmt.Sprintf("%v, commit %v, built at %v", version, commit, date)
}

func usage(err error) {
	fmt.Printf("Error: %v\n", err)
	fmt.Printf(`
Name:
  gembel - bulk update issue labels of GitHub repositories.

Version:
  %s

Usage:
  gembel <config-file>

  To specifiy GITHUB_TOKEN when running it:

  GITHUB_TOKEN=token gembel <config-file>
`, getVersion())

	os.Exit(1)
}
