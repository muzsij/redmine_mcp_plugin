# Redmine MCP

Connect MCP clients to the projects, issues, wikis, and users already managed by
Redmine. The plugin runs inside the Redmine process and exposes a Streamable HTTP
endpoint at `POST /mcp`; it uses Redmine's own users, authentication, permissions,
visibility rules, settings, and database instead of creating a parallel service.

Every tool runs as the authenticated Redmine user. Redmine permissions and record
visibility limit what that user can access, and OAuth2 scopes can narrow access
further. The endpoint is disabled after installation and, once enabled, starts in
read-only mode.

This is a fork of [serenysoft/redmine_mcp](https://github.com/serenysoft/redmine_mcp);
see [Differences from the original project](#differences-from-the-original-project).

## Quickstart

### 1. Install the plugin

Redmine 6.1 or later is required. From the root of a compatible Redmine checkout,
place this repository at `plugins/redmine_mcp`, install dependencies, and
run the required plugin migration:

```sh
git clone https://github.com/muzsij/redmine_mcp_plugin.git plugins/redmine_mcp
bundle install
bin/rails redmine:plugins:migrate NAME=redmine_mcp RAILS_ENV=production
```

Restart the Redmine application using the procedure for your deployment. Redmine
supplies the supported Ruby, Rails, database, and application-server environment;
this plugin is not a standalone Rails application.

When upgrading from `redmine_mcp_plugin`, rename its installation directory to
`plugins/redmine_mcp` before running the migration with `NAME=redmine_mcp`. Keep
only that directory installed. The migration transfers existing plugin settings
to the new identifier without overwriting settings already saved under it.
Previous migration records remain in the database; the guarded OAuth migration
can safely run again under the new plugin identifier. The MCP endpoint stays `/mcp`.

### 2. Enable and configure the endpoint

For the shortest first connection, use a Redmine API key:

1. In **Administration > Settings > API**, enable the REST web service.
2. In **Administration > Plugins > Redmine MCP > Configure**, enable the
   MCP endpoint. Leave **REST API key** and **Read-only mode** enabled.
3. Save the settings, then copy an active Redmine user's API access key from that
   user's **My account** page.

The REST API setting is also required for OAuth2 and HTTP Basic authentication.
Session-cookie authentication does not depend on it.

### 3. Configure an MCP client

Point the client at the Redmine base URL followed by `/mcp` and send the user's API
key in `X-Redmine-API-Key`. A typical HTTP MCP configuration looks like this:

```json
{
  "mcpServers": {
    "redmine": {
      "type": "http",
      "url": "https://redmine.example.com/mcp",
      "headers": {
        "X-Redmine-API-Key": "YOUR_API_KEY"
      }
    }
  }
}
```

Configuration keys vary by client. If the client manages OAuth2 authorization,
omit the API-key header and use the OAuth flow described under
[Authentication](#authentication).

### 4. Verify the connection

Call the read-only `whoami` tool directly to confirm the endpoint, credentials,
and effective server mode:

```sh
curl --fail-with-body https://redmine.example.com/mcp \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json, text/event-stream' \
  --header 'MCP-Protocol-Version: 2026-07-28' \
  --header 'Mcp-Method: tools/call' \
  --header 'Mcp-Name: whoami' \
  --header 'X-Redmine-API-Key: YOUR_API_KEY' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"curl","version":"1.0"}}}}'
```

A successful JSON-RPC response contains `result.structuredContent` with the
Redmine user's identity, `authentication_mode` set to `api_key`, and
`read_only_server` set to `true`. The configured MCP client can now discover the
other tools with `tools/list`.

## Authentication

Authentication modes are independently configurable under **Administration >
Plugins > Redmine MCP**.

| Mode | Default | Client credential and access |
|---|---:|---|
| OAuth2 | On | Send `Authorization: Bearer TOKEN`. Redmine issues per-user tokens whose scopes can narrow the user's permissions. |
| API key | On | Send `X-Redmine-API-Key: KEY`. The key carries the user's full permissions without OAuth scope narrowing. |
| HTTP Basic | Off | Send a username and password, or an API key as the username. Accounts with two-factor authentication enabled cannot use this mode. |
| Session cookie | Off | Reuse a logged-in browser session. Intended for browser-based clients and protected by the endpoint's Origin check. |

OAuth2 clients can be registered under **Administration > Applications**. The
plugin publishes protected-resource and authorization-server metadata at:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
```

The protected-resource metadata and the `/mcp` authentication challenge advertise
the scopes for an initial client handshake. In read-only mode these are the read
bootstrap scopes
`view_issues view_project view_wiki_pages view_issue_watchers view_time_entries
view_private_notes`. With read-only mode off they also include the scope of every
write tool (`add_issues edit_issues manage_issue_relations add_issue_notes
manage_versions edit_wiki_pages log_time edit_own_time_entries manage_subtasks
set_notes_private`), because clients such as Claude do not keep scopes gained
through step-up across reconnects. `admin` and `edit_time_entries` are still
requested only through step-up challenges. Each
challenge is logged as a `[redmine_mcp] insufficient_scope` warning that names the
tool, the required permissions and the token's scopes.

A client registered before this change keeps its narrower registered scopes.
Remove it from the client and reconnect so that it registers again.

Dynamic client registration (RFC 7591) is optional and disabled by default.
Enabling it exposes `POST /oauth/registration` so MCP clients can register
before completing Authorization Code with PKCE. Both public clients
(`token_endpoint_auth_method` `none`) and confidential clients
(`client_secret_basic` or `client_secret_post`, which Claude uses) are accepted.

Authentication is only the first boundary: a tool must also be allowed by the
user's Redmine permissions, OAuth scopes when present, and Redmine's record
visibility rules. See [Plugin architecture](ARCHITECTURE.md) for the request
flow, Origin policy, authorization layers, and other security invariants.

## Tools and write access

The available tool list varies with the authenticated user's access. Read-only
mode is on by default; while it is on, write tools are absent from `tools/list` and
are refused by `tools/call`.

For OAuth2 callers, `tools/list` reflects Redmine role permissions rather than
the current token's narrower scopes. A role-permitted tool can therefore be
discovered before scope elevation, but `tools/call` still enforces the current
token scopes; tools denied by the user's role remain hidden.

| Capability | Tools | Required Redmine permission |
|---|---|---|
| Identity | `whoami` | None |
| Projects | `list_projects`, `get_project` | `view_project` |
| Issues | `search_issues`, `get_issue` | `view_issues` |
| Status catalog | `list_statuses` | None |
| Versions | `list_versions` | `view_issues`; time totals also require `view_time_entries` |
| Groups | `get_group` | Filtered by Redmine principal visibility |
| Wiki pages | `list_wiki_pages`, `get_wiki_page` | `view_wiki_pages` |
| Metadata | `list_enumerations` | None |
| Users | `list_users` | Filtered by Redmine principal visibility |
| Issue custom fields | `list_issue_custom_fields` | `add_issues` |
| Create an issue | `create_issue` (optional `custom_fields`, by id or name; see `list_issue_custom_fields`) | `add_issues`; read-only mode must be disabled |
| Update an issue | `update_issue` | `edit_issues`; private notes also require `set_notes_private`; read-only mode must be disabled |
| Issue relations | `add_issue_relation` | `manage_issue_relations`; read-only mode must be disabled |
| Add an issue note | `add_issue_note` | `add_issue_notes`; private notes also require `set_notes_private`; read-only mode must be disabled |
| Time entries | `list_time_entries` | `view_time_entries`; includes filtered `total_hours` |
| Log time | `create_time_entry` | `log_time`; logs as the caller; read-only mode must be disabled |
| Edit or delete own time | `update_time_entry`, `delete_time_entry` | `edit_own_time_entries` or `edit_time_entries`; read-only mode must be disabled; deletion is marked destructive |
| Create a version | `create_version` | `manage_versions`; read-only mode must be disabled |
| Create a wiki page | `create_wiki_page` | `edit_wiki_pages`; read-only mode must be disabled |
| Upload a file | `create_attachment_upload`, `upload_attachment_content`, `upload_attachment_from_url` | Any permission that allows uploads in Redmine (for example `add_issues`, `edit_issues`, or `add_issue_notes`); read-only mode must be disabled; `upload_attachment_from_url` also requires the administrator setting |

Issue creation and updates accept status, category, target version, and parent issue.
Setting a parent also requires `manage_subtasks`. Redmine's workflow and safe
attributes still decide which changes are allowed.

`search_issues` accepts native Redmine filters through `filters`, including named
assignees/authors, status, dates, custom fields, and native numeric IDs. Conditions
are combined with AND. It searches all statuses by default; use `status: "open"`
or a native status filter to limit the result. Existing top-level filters and
`sort` remain supported and combine with the native filters.
Journal and watcher filters, including the history operators ("has been", "has
never been", "changed from"), use only records visible with the caller's roles
and OAuth scopes; private notes and other users' watches require their
respective read scopes. On Redmine 6.1 the native full-text `any_searchable`
filter is unavailable to an OAuth token without `view_private_notes` when the
caller's roles would grant it, because that version's search cannot apply the
token's narrowing; Redmine 7 narrows the search itself and keeps the filter. Spent-time filters and issue/version totals count only visible
records.

Tool arguments are validated against their declared schemas. The paginated
tools (`list_projects`, `search_issues`, `list_wiki_pages`, `list_users`, and `list_time_entries`)
support `limit` and `offset`, report pagination metadata, and cap each page at
the configured maximum (100 by default, with an absolute maximum of 1000).

## Attaching files

Attaching a file to an issue takes two steps, as in Redmine's REST API. First,
store the file as a pending upload and get a token. Then pass the token in the
`uploads` argument of `create_issue`, `update_issue`, or `add_issue_note`. Each
upload entry is `{token, filename?, description?, content_type?}`. A call accepts
at most 10 uploads. `add_issue_note` accepts uploads without note text. There are
three ways to get a token:

- **`create_attachment_upload`** is for a file in the client's own environment,
  such as Claude Code's machine or a code sandbox. It returns an `upload_url` that
  is valid for 15 minutes. Send the raw bytes there:

  ```sh
  curl --fail --data-binary @report.pdf -H "Content-Type: application/octet-stream" "UPLOAD_URL"
  ```

  The JSON response contains the token. The file never passes through the model.
  The environment must be able to reach Redmine over HTTP; some hosted sandboxes
  cannot.
- **`upload_attachment_from_url`** has the Redmine server download an `https`
  link, such as a pre-signed download link from another connector. Only links
  that work without the user's own credentials can succeed. This tool is off by
  default; see below.
- **`upload_attachment_content`** takes the file as base64 in the tool call. It
  is limited to 64 KiB, because the content passes through the conversation.

Redmine's attachment size limit and its allowed and denied extensions apply to
every path. A token can only be attached by the user who uploaded it. Uploads that
are never attached are removed by Redmine's `redmine:attachments:prune` task.

### Downloads from URLs

The **Attachment uploads** section of the plugin settings controls server-side
downloads:

- **Allow downloads from URLs** turns `upload_attachment_from_url` on. It is off
  by default.
- **Allowed download hosts** is an optional list of host names, one per line. Use
  `*.example.com` to match subdomains. When the list is empty, any host is
  allowed.
- **Allow internal addresses** is off by default. While it is off, URLs that
  resolve to loopback, private, link-local (including cloud metadata), or other
  non-public addresses are refused. Turn it on only if the server must reach
  intranet hosts.

Only `https` is supported. Redirects are followed at most three times, and each
hop is checked against the same rules. Proxy environment variables are not used.

## Prompts

The server also exposes user-invoked prompts through `prompts/list` and
`prompts/get`. A prompt renders instruction text the model then carries out with
the read tools above; the prompt itself reads no Redmine records, so prompts are
offered to every authenticated user and cannot widen what the caller may see.

| Prompt | Purpose |
|---|---|
| `generate_changelog` | Produce an Athena-style changelog for the visible issues of one project version filtered by a single tracker. Takes a single optional `request` argument: free text describing the desired changelog (which version, optional tracker, optional format notes). It may be omitted; the skill then asks what you want and resolves scope interactively through the read tools, defaulting to the house Athena format. |
| `qa_ticket_history_report` | Produce a scoped QA ticket-history report with São Paulo business-hour ownership, retest counting, and Dev/QA identification. Takes one optional `request`: free text naming a project/category/version and/or period, plus any format or calendar overrides. It may be omitted; the skill asks only for missing or ambiguous scope, proposes returned/reproved statuses from the real catalog for confirmation, and then uses the read tools. Weekends are excluded, holidays are not accounted for, and an open issue's ongoing owner interval is excluded from totals. |

Both prompts take a single free-text argument. The server offers no prompt-argument
completion capability. Request text is represented losslessly as inert data and is
never dereferenced, so a long body, path, URL, or delimiter-like text in your notes
is accepted rather than refused. The skills are read-only, and every read tool they
name independently enforces the caller's permissions and record visibility.

### Editing the prompts and tool descriptions

**Administration > Plugins > Redmine MCP > Configure** has two tabs of
model-facing text:

* **Prompts**: the text of both prompts, and the server instructions every
  client receives when it connects.
* **Tools**: each tool's description and each parameter's description, as
  sent in `tools/list`. Parameter names, types, and required parameters are not
  editable, because every call is validated against them. Clients usually fetch
  the tool list once per connection, so edits apply when they reconnect.

Each field starts with the built-in default. A field left at its default stores
nothing, so it keeps following the default when the plugin is updated; clearing
a field, or **Restore default**, goes back to it.

In a prompt's text, `{{request}}` marks where the caller's `request` goes,
together with the framing that tells the model to treat it as data. A text
without the marker gets that section appended at the end, so an edit cannot
drop the request. Prompt names, titles, descriptions, and arguments are not
editable.

## Resources (issue attachments)

The server declares the `resources` capability for one thing: the bytes of a file
attached to a visible issue. It is application- or user-selected context, not a
model-driven tool. `resources/list` is empty and `resources/templates/list`
publishes a single template:

```
redmine://issues/{issue_id}/attachments/{attachment_id}
```

Call `get_issue` with `include_attachments: true` to discover concrete
attachments: each is returned as metadata (including its `resource_uri` and a
credential-free `human_download_url`) and as a `resource_link` content block a
resource-aware client can select. Fetch the bytes with `resources/read` on the
`resource_uri`. The read runs as the authenticated user and rechecks issue and
attachment visibility every time, so a URI is not a capability.

Safe UTF-8 text is returned as `text`; every other type, including HTML and SVG,
is returned as a base64 `blob`. One read is capped at 5 MiB; a larger but visible
attachment is refused with a pointer to its `human_download_url`, which a user
already signed in to Redmine can open in a browser. The capability offers no
subscriptions or change notifications. OAuth callers need the `view_issues` scope
and are challenged to elevate to it when a narrower token is presented.

## Protocol behavior

The server accepts and advertises MCP revisions `2026-07-28`, `2025-11-25`, and
`2025-06-18`. Clients using the newest revision use the stateless
`server/discover` flow; compatibility clients use the `initialize` handshake
with either older revision.

The transport returns one JSON response per authenticated `POST /mcp`. It does not
provide SSE, server-to-client streams, transport sessions, or JSON-RPC batching.
After the endpoint's shared security gates pass, `GET /mcp` and `DELETE /mcp`
return 405. Non-browser clients normally omit `Origin`; every supplied Origin
must match the Redmine base URL or an additional origin configured by an
administrator.

## Development

This repository must be developed and tested as `plugins/redmine_mcp`
inside a compatible Redmine checkout. Run Rails, Rake, Bundler, migration, and
test commands from the Redmine root:

```sh
bundle install
bin/rails redmine:plugins:migrate NAME=redmine_mcp RAILS_ENV=development
bin/rails redmine:plugins:test NAME=redmine_mcp RAILS_ENV=test
RAILS_ENV=test bin/rails test plugins/redmine_mcp/test/unit/mcp_server_test.rb
```

See the [coding agent guide](AGENTS.md) for repository conventions and the
[architecture document](ARCHITECTURE.md) before changing protocol or
security boundaries. Redmine's official [plugin development
tutorial](https://www.redmine.org/projects/redmine/wiki/Plugin_Tutorial) is useful
background, but its examples target older Redmine versions; this repository's
current behavior, tests, and supported Redmine APIs take precedence.

## Differences from the original project

Forked from [serenysoft/redmine_mcp](https://github.com/serenysoft/redmine_mcp) at
commit `346f261`, which in turn builds on
[joaoperfig/redmine_mcp_plugin](https://github.com/joaoperfig/redmine_mcp_plugin).
Changes since then:

- **Attaching files:** `create_issue`, `update_issue`, and `add_issue_note` take an
  `uploads` argument. A file can reach Redmine through a signed, 15-minute upload
  URL from `create_attachment_upload`, so it never passes through the model;
  through a server-side download with `upload_attachment_from_url`, which is off by
  default, `https` only, and refuses internal addresses; or as up to 64 KiB of
  base64 with `upload_attachment_content`. See [Attaching files](#attaching-files).
- **Field changes always reach the history:** `update_issue` always opens a
  journal, so changes made without a note are recorded on the issue.
- **Works with Claude's connectors:** dynamic client registration accepts
  confidential clients (`client_secret_post` and `client_secret_basic`). Because
  Claude does not accumulate step-up grants, the first handshake already requests
  the write and private-note scopes when read-only mode is off. Read tools that
  need a write permission, such as `list_issue_custom_fields`, now get a scope
  challenge instead of a server error. Refused registrations and scope challenges
  are logged with their reason.
- **OAuth scopes on every read:** `get_issue` notes and spent hours,
  `list_versions` totals, `get_group` members, and the `search_issues` filters for
  notes, note authors, watchers, field history, full text, and spent time follow the
  token's scopes and Redmine's visibility rules. A token without
  `view_private_notes` or `view_issue_watchers` can neither read nor probe that
  data. Redmine's own classes are not patched.
- **Stricter authentication:** an HTTP Basic header with a blank username is
  refused instead of falling back to the browser session. Client registration
  accepts only absolute HTTP(S) redirect URIs without credentials or fragments,
  and plain HTTP only for loopback hosts.
- **Redmine 7 and Ruby 4:** besides Redmine 6.1, the plugin runs on Redmine 7.0
  with Ruby 4.0, where the spent-time filter also accepts durations such as `1:30`.
- **Tested** with the full test suite on Redmine 6.1 (Ruby 3.4) and Redmine 7.0
  (Ruby 4.0), and in production on Redmine 6.1 with claude.ai.

## License

This plugin is distributed under the GNU General Public License version 2 or
later. See [LICENSE](LICENSE).
