# Bridge between GitHub and Nostr

This project is a bidirectional bridge between GitHub and Nostr.

It allows using a bridge account and also allows users to optionally link their GitHub and Nostr account.  In the latter case, it will attribute the user's stuff to that user, otherwise to the bridge account.

## Recommended Installation

Have a GitHub organization which contains your repos.

Install the GitHub App "Friendly Machines GitHub Nostr" bridge on it--which is this project.

## GitHub App

The GitHub App registers for GitHub web hooks and also has ways of changing things in the GitHub repo view.

It entirely does metadata, git repository itself is not required.  In fact, it was tested on GitHub "repos" where there is no git repo, only issues etc.

## Cron job

The bridge runs via a cron job. It's recommended to install it to run every 2 minutes or so:

```
*/2 * * * * php /foo/v1/cron.php >> ~/bridge-cron.log 2>&1
```

## Logs

There are log files `github-webhook.log` and especially `bridge-cron.log` (see above) where you can see the bridge actions.

# Extra: NostrGit Web Client

There's a HTML5 NostrGit client included in the client/ directory.  It is intended to be installed into the directory where your git repositories are.
You can use it to show the user the "code" (content) of the repository, to create issues, PRs, patches and to submit tags to the Nostr network.

It requires a project.list file (same directory). You can create it like this:

```shell
ls -1 -d *.git >projects.list
```

It is recommended to also enable "smart" git hosting service--but it's optional.

If you want to enable it, you can do it like this:

Create a file `git.cgi` with this content:

```shell
#!/bin/sh
DIR="$(cd "$(dirname "$0")" && pwd)"
export GIT_PROJECT_ROOT="$DIR"
#export GIT_PROJECT_ROOT="$(dirname "$0")"

export GIT_HTTP_EXPORT_ALL=1
exec /usr/lib/git-core/git-http-backend
```

Create a file `.htaccess` with this content:

```shell
Options +ExecCGI
AddHandler cgi-script .cgi
AcceptPathInfo On

<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /git/

RewriteRule ^([^/]+\.git/.*)$ git.cgi/$1 [L,QSA]
RewriteRule ^([^/]+\.git)$ git.cgi/$1/ [L,QSA]
</IfModule>
```

This makes the git service much faster.

# Extra info: Repository mirroring

## Automatically git push to two destinations

```shell
git remote set-url --add --push origin user@example.com:git/xxx
git remote set-url --add --push origin user@git.foo.com:git/xxx
```

## Mirror repositories manually

```shell
git clone --mirror user@example.com:git/xxx xxx
git push --mirror user@git.foo.com:git/xxx
# Set HEAD on remote to match source default branch
ssh git.foo.com 'git symbolic-ref HEAD refs/heads/$DEFAULT_BRANCH'
```
