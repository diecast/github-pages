extern crate diecast;
extern crate docopt;
extern crate git2;
extern crate regex;
extern crate url;
extern crate rustc_serialize;

use std::path::PathBuf;
use std::process::Command;
use std::env;

use diecast::{Site, Configuration};

use docopt::Docopt;
use regex::Regex;
use url::Url;
use git2::Repository;

#[derive(RustcDecodable, Debug)]
struct Options {
    flag_jobs: Option<usize>,
    flag_verbose: bool,
    flag_remote: Option<String>,
    flag_branch: Option<String>,
}

static USAGE: &'static str = "
Usage:
    diecast <name> [options]

Options:
    -h, --help          Print this message
    -v, --verbose       Use verbose output
    --remote <name>     Push to a specific remote
    --branch <name>     Push to a specific branch

Deploy the site to GitHub Pages.
";

#[derive(Debug)]
pub struct GitHubPages {
    remote: String,
    branch: String,
    git: PathBuf,
}

/// Deploy the site to GitHub Pages
impl GitHubPages {
    pub fn new<R, B>(remote: R, branch: B) -> GitHubPages
        where R: AsRef<str>,
              B: AsRef<str>
    {
        // If there's a repo and a remote with the given remote name, obtain
        // it's url. Otherwise treat the remote as a remote url.
        let remote = Repository::open(".").and_then(|repo| {
            repo.find_remote(remote.as_ref()).map(|remote| {
                let url = remote.url().expect("remote url is not utf8");
                String::from(url)
            })
        }).unwrap_or_else(|_| String::from(remote.as_ref()));

        GitHubPages {
            remote: remote,
            branch: String::from(branch.as_ref()),
            git: PathBuf::from(".deploy.git/"),
        }
    }

    // TODO
    // this needs testing

    /// Detect the GitHub pages configuration
    ///
    /// If there's a single GitHub remote and the project name is `*.github.io`,
    /// it's assumed to be user or organization pages, in which case it is
    /// deployed to that remote's `master` branch.
    ///
    /// If there's a single GitHub remote and the project name doesn't match the
    /// above pattern, then it's assumed to be project pages, in which case it
    /// is deployed to that remote's `gh-pages` branch.
    ///
    /// If there is more than one candidate remote, the situation is ambiguous
    /// and the function panics. In this case you need to explicitly specify the
    /// remote and branch via `GitHubPages::new()`
    ///
    /// The logic follows the information on GitHub:
    ///
    /// | Type                       | Default Domain                   | Branch   |
    /// | -------------------------- | -------------------------------- | -------- |
    /// | user pages                 | `username.github.io`             | master   |
    /// | organization pages         | `orgname.github.io`              | master   |
    /// | user project pages         | `username.github.io/projectname` | gh-pages |
    /// | organization project pages | `orgname.github.io/projectname`  | gh-pages |
    ///
    /// source: https://help.github.com/articles/user-organization-and-project-pages/

    pub fn detect() -> Result<GitHubPages, git2::Error> {
        let repo = try!(Repository::open("."));
        let remotes = try!(repo.remotes());

        let git_re = git_url_pattern();

        let mut candidates = vec![];

        for name in remotes.iter() {
            let name = name.expect("remote name is not utf8");
            let remote = try!(repo.find_remote(name));
            let url = remote.url().expect("remote url is not utf8");

            let user_project = if url.starts_with("git@") {
                parse_git_url(url, &git_re)
            } else {
                parse_http_url(url)
            };

            let (user, project) = match user_project {
                Some(pair) => pair,
                None => continue,
            };

            let project_re = Regex::new(&format!("{}.github.(?:io|com)", user))
                                 .expect("regex syntax error");

            let pages_type = if !project_re.is_match(&project) {
                // root pages
                PagesType::Root
            } else {
                // project pages
                PagesType::Project
            };

            candidates.push(Candidate {
                remote: url.to_string(),
                pages_type: pages_type,
            });
        }

        match candidates.len() {
            0 => panic!("no candidates found"),
            1 => Ok(GitHubPages::from(candidates.remove(0))),
            _ => panic!("more than one candidate found: {:?}", candidates),
        }
    }

    /// Set the desired remote url to push to.
    pub fn remote<S>(mut self, remote: S) -> GitHubPages
        where S: Into<String>
    {
        self.remote = remote.into();
        self
    }

    /// Set the desired target branch to push to.
    pub fn branch<S>(mut self, branch: S) -> GitHubPages
        where S: Into<String>
    {
        self.branch = branch.into();
        self
    }

    /// Set the desired git deploy directory.
    pub fn git<P>(mut self, git: P) -> GitHubPages
        where P: Into<PathBuf>
    {
        self.git = git.into();
        self
    }

    fn configure(&mut self, configuration: &mut Configuration) {
        // 1. merge options into configuration; options overrides config
        // 2. construct site from configuration
        // 3. build site

        let docopt = Docopt::new(USAGE)
                         .unwrap_or_else(|e| e.exit())
                         .help(true);

        let options: Options = docopt.decode().unwrap_or_else(|e| {
            e.exit();
        });

        if let Some(jobs) = options.flag_jobs {
            configuration.threads = jobs;
        }

        // TODO
        // this verbosity flag should only affect this cmd, so it
        // doesn't make sense that it's setting the verbosity flag
        // for diecast overall?
        configuration.is_verbose = options.flag_verbose;

        if let Some(remote) = options.flag_remote {
            self.remote = remote;
        }

        if let Some(branch) = options.flag_branch {
            self.branch = branch;
        }
    }
}

impl From<Candidate> for GitHubPages {
    fn from(candidate: Candidate) -> GitHubPages {
        let branch = match candidate.pages_type {
            PagesType::Root => String::from("master"),
            PagesType::Project => String::from("project"),
        };

        GitHubPages {
            remote: candidate.remote,
            branch: branch,
            git: PathBuf::from("./deploy.git"),
        }
    }
}

impl diecast::Command for GitHubPages {
    fn description(&self) -> &'static str {
        "Deploy the site to GitHub Pages"
    }

    fn run(&mut self, site: &mut Site) -> diecast::Result<()> {
        self.configure(site.configuration_mut());

        let output = site.configuration().output.clone();

        try!(site.build());

        // git rev-list --oneline --max-count=1 HEAD
        let out = Command::new("git")
                      .arg("rev-list")
                      .arg("--oneline")
                      .arg("--max-count=1")
                      .arg("HEAD")
                      .output()
                      .unwrap_or_else(|e| panic!("git rev-list failed: {}", e));

        let (sha, message) = out.stdout.split_at(7);

        let sha = String::from_utf8_lossy(sha);
        let message = String::from_utf8_lossy(message);

        // has the repo been initialized?
        let initialized = diecast::support::file_exists(&self.git);

        if !initialized {
            println!("  [*] initializing repository");
            // git init --separate-git-dir .deploy.git
            Command::new("git")
                .arg("init")
                .arg("--bare")
                .arg(&self.git)
                .status()
                .unwrap_or_else(|e| panic!("git init failed: {}", e));
        }

        env::set_var("GIT_DIR", &self.git);
        env::set_var("GIT_WORK_TREE", &output);

        if !initialized {
            println!("  [*] setting up remote: github-pages = {}", self.remote);
            // git remote add github-pages <remote>
            Command::new("git")
                .arg("remote")
                .arg("add")
                .arg("github-pages")
                .arg(&self.remote)
                .status()
                .unwrap_or_else(|e| panic!("git remote failed: {}", e));

            println!("  [*] fetching remote: github-pages");
            // git fetch github-pages
            Command::new("git")
                .arg("fetch")
                .arg("github-pages")
                .status()
                .unwrap_or_else(|e| panic!("git fetch failed: {}", e));

            println!("  [*] resetting to {}", self.branch);
            // git reset github-pages/master
            Command::new("git")
                .arg("reset")
                .arg(format!("github-pages/{}", self.branch))
                .status()
                .unwrap_or_else(|e| panic!("git reset failed: {}", e));
        }

        Command::new("git")
            .arg("update-index")
            .arg("-q")
            .arg("--refresh")
            .status()
            .unwrap_or_else(|e| panic!("git update-index failed: {}", e));

        // git diff-index --quiet HEAD --
        let status = Command::new("git")
            .arg("diff-index")
            .arg("--quiet")
            .arg("HEAD")
            .arg("--")
            .status()
            .unwrap_or_else(|e| panic!("git diff-index failed: {}", e));

        if status.success() {
            println!("  [*] no changes found; exiting");
            return Ok(());
        }

        println!("  [*] staging all changes");
        // git add --all .
        Command::new("git")
            .arg("add")
            .arg("--all")
            .arg(".")
            .status()
            .unwrap_or_else(|e| panic!("git add failed: {}", e));

        println!("  [*] committing site generated from {}: {}", sha, message);
        // git commit -m "generated from <sha>"
        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg(format!("generated from {}", sha))
            .status()
            .unwrap_or_else(|e| panic!("git commit failed: {}", e));

        println!("  [*] pushing");
        // git push github-pages HEAD:master -f
        Command::new("git")
            .arg("push")
            .arg("github-pages")
            .arg("master")
            .arg("-f")
            .status()
            .unwrap_or_else(|e| panic!("git push failed: {}", e));

        env::remove_var("GIT_DIR");
        env::remove_var("GIT_WORK_TREE");

        println!("  [*] deploy complete");

        Ok(())
    }
}

#[derive(Debug)]
enum PagesType {
    Root,
    Project,
}

#[derive(Debug)]
struct Candidate {
    remote: String,
    pages_type: PagesType,
}

fn git_url_pattern() -> Regex {
    Regex::new(r"^git@github.com:(?P<user>.+)/(?P<project>.+)\.git")
        .expect("regex syntax error")
}

// git@github.com:blaenk/dots.git
fn parse_git_url(url: &str, re: &Regex) -> Option<(String, String)> {
    re.captures(url).and_then(|cap| {
        cap.name("user").and_then(|user| {
            cap.name("project").map(|project| {
                (String::from(user), String::from(project))
            })
        })
    })
}

#[test]
fn test_git_url() {
    let git_re = git_url_pattern();

    let (user, project) =
        parse_git_url("git@github.com:blaenk/dots.git", &git_re).unwrap();

    assert_eq!(user, "blaenk");
    assert_eq!(project, "dots");
}

fn parse_http_url(url: &str) -> Option<(String, String)> {
    let parsed = Url::parse(url).expect(&format!("couldn't parse remote url {}", url));

    match parsed.host_str() {
        Some("github.com") => (),
        Some(_) => return None,
        None => return None,
    }

    parsed.path_segments().map(|iter| {
        let segments: Vec<&str> = iter.collect();

        let user = segments[0].to_string();
        let project = segments[1].trim_right_matches(".git").to_string();

        (user, project)
    })
}

#[test]
fn test_http_url() {
    let urls = &[
        "https://github.com/blaenk/dots.git",
        "https://blaenk@github.com/blaenk/dots.git",
        "git://github.com/blaenk/dots.git",
        "git+https://github.com/blaenk/dots.git",
        "git+ssh://github.com/blaenk/dots.git"
    ];

    for url in urls {
        let (user, project) = parse_http_url(url).unwrap();

        assert_eq!(user, "blaenk");
        assert_eq!(project, "dots");
    }
}
