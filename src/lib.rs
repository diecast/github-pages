extern crate diecast;
extern crate docopt;
extern crate git2;
extern crate regex;
extern crate url;
extern crate rustc_serialize;

use std::path::{Path, PathBuf};
use std::cell::RefCell;
use std::{fs, env};

use diecast::{Site, Configuration};

use docopt::Docopt;
use regex::Regex;
use url::Url;
use git2::Repository;

// TODO
// check what gitlab's pages is like
// see if this can be made to work with it
// in that case, merge this with diecast-git?

#[derive(RustcDecodable, Debug)]
struct Options {
    flag_jobs: Option<usize>,
    flag_verbose: bool,
    flag_target_remote: Option<String>,
    flag_target_branch: Option<String>,
    flag_deploy_dir: Option<PathBuf>,
}

static USAGE: &'static str = "
Usage:
    diecast <name> [options]

Options:
    -h, --help                 Print this message
    -v, --verbose              Use verbose output
    --target-remote <name>     Push to a specific remote
    --target-branch <name>     Push to a specific branch
    --deploy-dir <path>        Directory for deployment temporary files

Deploy the site to GitHub Pages.
";

#[derive(Debug)]
pub enum BuildFrom {
    /// Specifies a particular revision to build from.
    ///
    /// This can be any revision which can be parsed by `git rev-parse`, for
    /// example `"HEAD"`, `"origin/master"`, etc.
    ///
    /// Under the hood this checks out the input directory at the state it was
    /// in for the specified revision.
    Revision(String),

    /// Specifies to build from the working tree.
    WorkingTree
}

#[derive(Debug)]
pub struct GitHubPages {
    /// The target remote to push to.
    ///
    /// This can be the name of a remote in the current git repository, or it
    /// can be a remote URL if it's another repository.
    ///
    /// e.g. `"origin"` or `"git@github.com:user/user.github.io.git"`
    target_remote: String,

    /// The target branch to push to.
    ///
    /// e.g. `"master"` or `"gh-pages"`
    target_branch: String,

    /// The directory to use to house the deployment files.
    ///
    /// Defaults to `.deploy/`, relative to the project root.
    deploy_dir: PathBuf,

    /// The revision to build from.
    ///
    /// Defaults to `Revision("HEAD")`, i.e. it'll build from the tree of the
    /// latest commit.
    ///
    /// You can set it to `Revision("origin/master")` for example to only build
    /// from the changes that have been pushed to origin remote so far. This way
    /// you can continue to make local commits without accidentally pushing a
    /// build from those potentially work-in-progress commits.
    build_from: BuildFrom,
}

/// Deploy the site to GitHub Pages
impl GitHubPages {
    pub fn new<R, B>(target_remote: R, target_branch: B) -> GitHubPages
        where R: AsRef<str>,
              B: AsRef<str>
    {
        // If there's a repo and a remote with the given remote name, obtain
        // it's url. Otherwise treat the remote as a remote url.
        let target_remote = Repository::discover(".").and_then(|repo| {
            repo.find_remote(target_remote.as_ref()).map(|remote| {
                String::from(remote.url().expect("remote url is not utf8"))
            })
        }).unwrap_or_else(|_| String::from(target_remote.as_ref()));

        GitHubPages {
            target_remote: target_remote,
            target_branch: String::from(target_branch.as_ref()),
            deploy_dir: PathBuf::from(".deploy/"),
            build_from: BuildFrom::Revision(String::from("HEAD")),
        }
    }

    // TODO
    // perhaps this is too magical? it's not too difficult to just do
    // GitHubPages::new("origin", "master");

    /// Detect the GitHub pages configuration
    ///
    /// Note that this assumes that the source and target repositories are the same.
    ///
    /// If there's a single GitHub remote and the project name is `*.github.io`,
    /// it's assumed to be user or organization pages, in which case it is
    /// deployed to that remote's `master` branch.
    ///
    /// If there's a single GitHub remote and the project name doesn't match the
    /// above pattern, then it's assumed to be project pages, in which case it
    /// is deployed to that remote's `gh-pages` branch.
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
    ///
    /// # Panics
    ///
    /// If there is more than one candidate remote, the situation is ambiguous
    /// and the function panics. In this case you need to explicitly specify the
    /// remote and branch via `GitHubPages::new()`

    pub fn detect() -> Result<GitHubPages, git2::Error> {
        let repo = try!(Repository::discover("."));
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
                PagesType::Root
            } else {
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

    /// Specify where to build from.
    pub fn build_from(mut self, build_from: BuildFrom) -> GitHubPages {
        self.build_from = build_from;
        self
    }

    /// Set the desired remote url to push to.
    pub fn target_remote<S>(mut self, remote: S) -> GitHubPages
        where S: Into<String>
    {
        self.target_remote = remote.into();
        self
    }

    /// Set the desired target branch to push to.
    pub fn target_branch<S>(mut self, branch: S) -> GitHubPages
        where S: Into<String>
    {
        self.target_branch = branch.into();
        self
    }

    /// Set the desired git deploy directory.
    pub fn deploy_dir<P>(mut self, deploy_dir: P) -> GitHubPages
        where P: Into<PathBuf>
    {
        self.deploy_dir = deploy_dir.into();
        self
    }

    fn configure(&mut self, configuration: &mut Configuration) {
        // 1. merge options into configuration; options overrides config
        // 2. construct site from configuration
        // 3. build site

        let docopt = Docopt::new(USAGE).unwrap_or_else(|e| e.exit()).help(true);

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

        if let Some(remote) = options.flag_target_remote {
            self.target_remote = remote;
        }

        if let Some(branch) = options.flag_target_branch {
            self.target_branch = branch;
        }

        if let Some(path) = options.flag_deploy_dir {
            self.deploy_dir = path;
        }
    }

    /// Checkout pathspec `input_dir` from `rev` into `deploy_dir`
    fn checkout_rev<'repo>(repo: &'repo Repository, rev: &str, input_dir: &Path, deploy_dir: &Path)
                           -> Result<git2::Object<'repo>, git2::Error> {
        let mut checkout_options = git2::build::CheckoutBuilder::new();
        checkout_options
            .update_index(false)
            .remove_untracked(true)
            .remove_ignored(true)
            .progress(|path, completed_steps, total_steps| {
                if let Some(p) = path {
                    println!("[{}/{}] {}",
                             completed_steps,
                             total_steps,
                             p.display());
                }
            })
            .path(input_dir)
            .target_dir(&deploy_dir)
            .force();

        let commit = try!(repo.revparse_single(rev)
                          .and_then(|r| r.peel(git2::ObjectType::Commit)));

        let tree = try!(commit.peel(git2::ObjectType::Tree));

        let old_workdir = repo.workdir().unwrap().to_path_buf();

        try!(repo.set_workdir(&deploy_dir, false));
        try!(repo.checkout_tree(&tree, Some(&mut checkout_options)));
        try!(repo.set_workdir(&old_workdir, false));

        Ok(commit)
    }

    fn clone_publish(remote_url: &str, repo: &Path, branch: &str, state: &RefCell<callbacks::CloneProgressState>)
                     -> Result<git2::Repository, git2::Error> {
        let mut remote_callbacks = git2::RemoteCallbacks::new();
        remote_callbacks
            .credentials(callbacks::credential)
            .transfer_progress(|stats| {
                let mut state = state.borrow_mut();
                state.progress = Some(stats.to_owned());
                callbacks::print_clone_state(&mut *state);
                true
            });

        let mut checkout_builder = git2::build::CheckoutBuilder::new();
        checkout_builder.progress(|path, cur, total| {
            let mut state = state.borrow_mut();
            state.path = path.map(|p| p.to_path_buf());
            state.current = cur;
            state.total = total;
            callbacks::print_clone_state(&mut *state);
        });

        let mut fetch_options = git2::FetchOptions::new();
        fetch_options.remote_callbacks(remote_callbacks);

        let mut repo_builder = git2::build::RepoBuilder::new();
        repo_builder
            .bare(true)
            .fetch_options(fetch_options)
            .branch(branch);

        repo_builder.clone(remote_url, repo)
    }

    fn statuses(publish_repo: &Repository) -> Result<git2::Statuses, git2::Error> {
        let mut status_options = git2::StatusOptions::new();
        status_options
            .show(git2::StatusShow::IndexAndWorkdir)
            .include_untracked(false)
            .include_ignored(false)
            .include_unmodified(false)
            .exclude_submodules(true)
            .recurse_untracked_dirs(false)
            .recurse_ignored_dirs(false)
            .no_refresh(true);

        // check here if there are diff index to working dir
        publish_repo.statuses(Some(&mut status_options))
    }

    fn commit(publish_repo: &Repository, tree_oid: git2::Oid,
              gen_from_commit: Option<git2::Object>) -> Result<(), git2::Error> {
        let commit_tree = try!(publish_repo.find_tree(tree_oid));

        let commit = match publish_repo.head() {
            Ok(head) => {
                let peeled = head.peel(git2::ObjectType::Commit)
                    .unwrap_or_else(|_| panic!("couldn't resolve HEAD to a commit"));

                let commit = peeled.into_commit()
                    .unwrap_or_else(|_| panic!("couldn't convert to commit"));

                Some(commit)
            },
            Err(_) => None,
        };

        // this must go after commit is init cause vars are destroyed in reverse
        // init order, so the commit would be destroyed, yielding a dangling
        // reference for the vec containing the refs
        let mut parents = vec![];

        if let Some(ref commit) = commit {
            parents.push(commit);
        }

        let author_sig = try!(publish_repo.signature());

        let gen_from = if let Some(commit) = gen_from_commit {
            let commit_id = commit.short_id().unwrap();
            commit_id.as_str().unwrap().to_string()
        } else {
            String::from("the working tree")
        };

        let _commit_oid = try!(publish_repo.commit(Some("HEAD"),
                                                   &author_sig, // author sig
                                                   &author_sig, // committer sig
                                                   &format!("generated from {}", gen_from),
                                                   &commit_tree,
                                                   &parents));

        Ok(())
    }

    fn fetch(remote: &mut git2::Remote, branch: &str) -> Result<(), git2::Error> {
        println!("  [*] connected for fetch");

        let mut cb = git2::RemoteCallbacks::new();
        cb.credentials(callbacks::credential);
        cb.sideband_progress(callbacks::sideband_progress);
        cb.update_tips(callbacks::update_tips);
        cb.transfer_progress(callbacks::transfer_progress);

        let mut fetch_options = git2::FetchOptions::new();
        fetch_options.remote_callbacks(cb);

        // TODO
        // sub 'master' for e.g. gh-pages
        println!("  [*] downloading fetch");
        let refspec = format!("refs/heads/{branch}:refs/remotes/origin/{branch}", branch=branch);

        try!(remote.fetch(&[&refspec], Some(&mut fetch_options), None));

        {
            // If there are local objects (we got a thin pack), then tell the user
            // how many objects we saved from having to cross the network.
            let stats = remote.stats();
            if stats.local_objects() > 0 {
                println!("\rReceived {}/{} objects in {} bytes (used {} local \
                          objects)", stats.indexed_objects(),
                         stats.total_objects(), stats.received_bytes(),
                         stats.local_objects());
            } else {
                println!("\rReceived {}/{} objects in {} bytes",
                         stats.indexed_objects(), stats.total_objects(),
                         stats.received_bytes());
            }
        }

        Ok(())
    }

    fn push(remote: &mut git2::Remote, branch: &str) -> Result<(), git2::Error> {
        let mut cb = git2::RemoteCallbacks::new();

        cb.credentials(callbacks::credential);
        cb.sideband_progress(callbacks::sideband_progress);
        cb.update_tips(callbacks::update_tips);
        cb.transfer_progress(callbacks::transfer_progress);

        let mut push_options = git2::PushOptions::new();
        push_options.remote_callbacks(cb);

        let refspec = format!("refs/heads/{branch}:refs/heads/{branch}", branch=branch);

        try!(remote.push(&[&refspec], Some(&mut push_options)));

        Ok(())
    }
}

impl From<Candidate> for GitHubPages {
    fn from(candidate: Candidate) -> GitHubPages {
        let branch = match candidate.pages_type {
            PagesType::Root => String::from("master"),
            PagesType::Project => String::from("project"),
        };

        GitHubPages::new(candidate.remote, branch)
    }
}

impl diecast::Command for GitHubPages {
    fn description(&self) -> &'static str {
        "Deploy the site to GitHub Pages"
    }

    fn run(&mut self, site: &mut Site) -> diecast::Result<()> {
        self.configure(site.configuration_mut());

        let repo = try!(Repository::discover("."));

        let state = RefCell::new(callbacks::CloneProgressState {
            progress: None,
            total: 0,
            current: 0,
            path: None,
            newline: false,
        });

        if !self.deploy_dir.exists() {
            try!(fs::create_dir(&self.deploy_dir));
        }

        self.deploy_dir = self.deploy_dir.canonicalize().unwrap();

        let commit = if let BuildFrom::Revision(ref rev) = self.build_from {
            println!("  [*] checking out {}", rev);
            Some(try!(GitHubPages::checkout_rev(&repo, rev, &site.configuration().input,
                                                &self.deploy_dir)))
        } else {
            None
        };

        // build
        println!("  [*] building");

        let old_current_dir = if let BuildFrom::Revision(_) = self.build_from {
            // need to set dir so that paths are the same as during normal build
            // in short, current dir has to be the one that contains the input/ dir
            let old_current_dir = env::current_dir().unwrap();
            try!(env::set_current_dir(&self.deploy_dir));
            Some(old_current_dir)
        } else {
            site.configuration_mut().output = self.deploy_dir.join("output");
            None
        };

        try!(site.build());

        // deploy
        let output_dir = site.configuration().output.clone();
        let publish_dir = self.deploy_dir.join("publish.git");

        println!("output: {:?}", output_dir);
        println!("publish: {:?}", publish_dir);

        let publish_repo = if !publish_dir.exists() {
            println!("  [*] cloning publish repo");
            try!(GitHubPages::clone_publish(&self.target_remote,
                                            &publish_dir, &self.target_branch, &state))
        } else {
            let open_flags = git2::REPOSITORY_OPEN_BARE | git2::REPOSITORY_OPEN_NO_SEARCH;
            try!(Repository::open_ext(&publish_dir, open_flags, vec![&self.deploy_dir]))
        };

        try!(publish_repo.set_workdir(&output_dir, false));

        let mut origin = try!(publish_repo.find_remote("origin"));

        println!("  [*] fetching");
        try!(GitHubPages::fetch(&mut origin, &self.target_branch));

        println!("  [*] resetting");
        let oid = try!(publish_repo.refname_to_id("refs/remotes/origin/master"));
        let object = try!(publish_repo.find_object(oid, None));
        try!(publish_repo.reset(&object, git2::ResetType::Mixed, None));

        // add to index
        let mut index = try!(publish_repo.index());

        let mut add_cb = |path: &Path, _matched_spec: &[u8]| -> i32 {
            let status = publish_repo.status_file(path).unwrap();

            // return 0 to confirm operation, > 0 to skip item, < 0 to abort scan
            if status.contains(git2::STATUS_WT_MODIFIED) || status.contains(git2::STATUS_WT_NEW) {
                0
            } else {
                1
            }
        };

        println!("  [*] adding");
        try!(index.add_all(vec!["."], git2::ADD_DEFAULT, Some(&mut add_cb)));

        let statuses = try!(GitHubPages::statuses(&publish_repo));

        if statuses.len() == 0 {
            try!(index.clear());

            println!("no changes");
        } else {
            println!("files changed: {}", statuses.len());

            for status in statuses.iter() {
                println!("  + {}", status.path().unwrap());
            }

            let tree_oid = try!(index.write_tree());

            println!("  [*] committing");
            try!(GitHubPages::commit(&publish_repo, tree_oid, commit));

            println!("  [*] pushing");
            try!(GitHubPages::push(&mut origin, &self.target_branch));
        }

        if let Some(old_current_dir) = old_current_dir {
            try!(env::set_current_dir(&old_current_dir));
        }

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

mod callbacks {
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::str;

    use git2;

    pub fn credential(_url: &str, username_from_url: Option<&str>,
                      _allowed_types: git2::CredentialType)
                      -> Result<git2::Cred, git2::Error> {
        git2::Cred::ssh_key_from_agent(username_from_url.unwrap())
    }

    pub fn sideband_progress(data: &[u8]) -> bool {
        print!("remote: {}", str::from_utf8(data).unwrap());
        io::stdout().flush().unwrap();
        true
    }

    // This callback gets called for each remote-tracking branch that gets
    // updated. The message we output depends on whether it's a new one or an
    // update.
    pub fn update_tips(refname: &str, a: git2::Oid, b: git2::Oid) -> bool {
        if a.is_zero() {
            println!("[new]     {:20} {}", b, refname);
        } else {
            println!("[updated] {:10}..{:10} {}", a, b, refname);
        }
        true
    }

    // Here we show processed and total objects in the pack and the amount of
    // received data. Most frontends will probably want to show a percentage and
    // the download rate.
    pub fn transfer_progress(stats: git2::Progress) -> bool {
        if stats.received_objects() == stats.total_objects() {
            print!("Resolving deltas {}/{}\r", stats.indexed_deltas(),
                   stats.total_deltas());
        } else if stats.total_objects() > 0 {
            print!("Received {}/{} objects ({}) in {} bytes\r",
                   stats.received_objects(),
                   stats.total_objects(),
                   stats.indexed_objects(),
                   stats.received_bytes());
        }
        io::stdout().flush().unwrap();
        true
    }

    pub struct CloneProgressState {
        pub progress: Option<git2::Progress<'static>>,
        pub total: usize,
        pub current: usize,
        pub path: Option<PathBuf>,
        pub newline: bool,
    }

    pub fn print_clone_state(state: &mut CloneProgressState) {
        let stats = state.progress.as_ref().unwrap();
        let network_pct = (100 * stats.received_objects()) / stats.total_objects();
        let index_pct = (100 * stats.indexed_objects()) / stats.total_objects();
        let co_pct = if state.total > 0 {
            (100 * state.current) / state.total
        } else {
            0
        };
        let kbytes = stats.received_bytes() / 1024;
        if stats.received_objects() == stats.total_objects() && false {
            if !state.newline {
                println!("");
                state.newline = true;
            }
            print!("Resolving deltas {}/{}\r", stats.indexed_deltas(),
                   stats.total_deltas());
        } else {
            print!("net {:3}% ({:4} kb, {:5}/{:5})  /  idx {:3}% ({:5}/{:5})  \
                    /  chk {:3}% ({:4}/{:4}) {}\r",
                   network_pct, kbytes, stats.received_objects(),
                   stats.total_objects(),
                   index_pct, stats.indexed_objects(), stats.total_objects(),
                   co_pct, state.current, state.total,
                   state.path.as_ref().map(|s| s.to_string_lossy().into_owned())
                   .unwrap_or(String::new()));
        }
        io::stdout().flush().unwrap();
    }
}
