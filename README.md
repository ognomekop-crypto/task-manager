# Task Manager

A Rust-based task scheduler and automation tool with a native GUI and background service. Designed for Windows, it supports time-based, email-based, and webhook-based triggers with Pushover notifications and Cloudflare DNS integration.

## Features

### Triggers
- **Specific Time** — Daily at a set hour/minute
- **Days of Week** — Run on selected weekdays at a set time
- **Interval** — Every N minutes
- **Email** — Triggered by incoming emails matching from/subject/body patterns (built-in SMTP server)
- **ntfy.sh** — Triggered by published messages on ntfy.sh topics (subscribe mode)
- **Startup** — Run once when the service starts
- **On Demand** — Execute only when called by another task via task chaining

### Task Types
- **HTTP GET / POST** — Make web requests with custom headers and body
- **Command** — Execute shell commands via `cmd /C`
- **Path Check** — Verify a directory or file exists (file path is resolved relative to the checked path)
- **File Changed** — Detect when a file's SHA-256 hash changes from a baseline
- **ntfy.sh** — Publish messages or subscribe to topics
- **Get Public IP** — Fetch and save your public IP address
- **Cloudflare DNS Update** — Automatically update DNS A/AAAA records, with **per-task encrypted credentials**, global fallback defaults, and **variable substitution on all fields including proxied and TTL**
- **Cloudflare IP List Update** — Add, remove, or replace IPs in Cloudflare Rules IP Lists (firewall allowlists/blocklists), with per-task credentials and list name lookup

### Variable Substitution
When a task is triggered by an **ntfy.sh** message, the incoming message fields are available as variables in **any text field** of that task (including chained tasks):

| Variable | Description |
|----------|-------------|
| `{{ntfy_topic}}` | The ntfy topic that triggered the task |
| `{{ntfy_title}}` | The title of the incoming ntfy message |
| `{{ntfy_message}}` | The body of the incoming ntfy message |
| `{{ntfy_tags1}}` | First tag from the incoming message |
| `{{ntfy_tags2}}` | Second tag from the incoming message |
| `{{ntfy_tagsN}}` | Nth tag (1-based) from the incoming message |
| `{{public_ip}}` | The last saved public IP address |

These variables are substituted at execution time in:
- HTTP URLs, bodies, and headers
- Command arguments and working directories
- Path and file check paths
- ntfy publish title, message, topic, and tags
- Cloudflare DNS **zone ID, record name, record ID, content, proxied, and TTL**
- Cloudflare IP List **account ID, list ID, list name, IP, and comment**
- **Pushover notification titles and messages**
- Task chaining (the context propagates to chained tasks)

### Notifications
- **Pushover** — Per-task notification settings with custom titles, messages, priority, and sound
- **Notify When** — Success only, failure only, or both

### Security
- **Master Password** — PBKDF2 + AES-256-GCM encryption for Pushover and Cloudflare credentials
  - **Required** — You must set a master password before saving any encrypted credentials (Pushover or Cloudflare). The GUI will show an error if you try to save credentials without one.
- **Password Verification** — SHA-256 verifier stored with random salt
- **Per-Task Encryption** — Cloudflare API tokens can be encrypted per-task, allowing different zones/accounts to use different credentials

### Task Chaining
- Link tasks to run on **success** or **failure** of another task
- **On Demand** tasks are never triggered by time/email/ntfy — they only run when chained
- Chain depth limited to 10 to prevent infinite loops

### Architecture
- **Service Binary** (`task_manager_service`) — Background Tokio async runtime handling scheduling, SMTP, ntfy SSE listeners, and task execution
- **GUI Binary** (`task_manager_gui`) — Native egui/eframe desktop application for task configuration, service control, log viewing, and settings
- **Hot Reload** — Service automatically reloads `config.json` when modified
- **Status File** — Service writes `status.json` for GUI polling of task run states
- **Rotating Logs** — Daily log files with automatic 7-day cleanup
- **Stable Config Directory** — Config and logs are stored alongside the executable, ensuring the service and GUI always share the same files regardless of working directory

## Building

Requires [Rust](https://rustup.rs/) (edition 2021).

```bash
cargo build --release
```

This produces:
- `target/release/task_manager_service.exe`
- `target/release/task_manager_gui.exe`

## Running

1. Start the GUI:
   ```bash
   cargo run --bin task_manager_gui
   ```

2. Configure settings (master password, SMTP port, Pushover/Cloudflare credentials, and Cloudflare defaults).

3. Start the service from the GUI or manually:
   ```bash
   TASK_MANAGER_PASSWORD=your_password cargo run --bin task_manager_service
   ```

## Configuration

All settings and tasks are stored in `config.json` in the executable's directory:

```json
{
  "smtp_port": 25,
  "pushover_app_token_encrypted": "...",
  "pushover_user_key_encrypted": "...",
  "cloudflare_api_token_encrypted": "...",
  "cloudflare_api_email_encrypted": "...",
  "cloudflare_default_zone_id": "...",
  "cloudflare_default_record_name": "...",
  "cloudflare_default_proxied": "true",
  "cloudflare_default_ttl": "60",
  "password_verifier": "...",
  "password_salt": "...",
  "public_ip": "1.2.3.4",
  "tasks": []
}
```

### Per-Task Cloudflare Credentials

Each Cloudflare DNS Update task can store its own encrypted API token and account email. When editing a Cloudflare task in the GUI, you will see **Per-Task Cloudflare Credentials** fields:

- **API Token** — Enter a Cloudflare API Token (or Global API Key) specific to this task
- **Account Email** — Required only when using a Global API Key

Leave these fields empty to fall back to the **global Cloudflare credentials** configured in Settings.

### Cloudflare IP Lists

The **Cloudflare IP List Update** task type manages IP addresses in Cloudflare Rules IP Lists (used in firewall rules, access policies, etc.).

Supported actions:
- **Add** — Append an IP to the list. If the IP **already exists** in the list (regardless of comment), nothing is changed. If the IP is new but a **comment** is provided and an existing entry has the same comment, the old entry is deleted and the new one is added.
- **Remove** — Delete an IP from the list (looks up by IP address)
- **Replace All** — Clear the list and add only the specified IP

Fields:
- **Account ID** — Your Cloudflare account ID
- **List ID** — The IP List ID (leave empty to look up by name)
- **List Name** — Human-readable list name (used for lookup when List ID is empty)
- **IP** — The IP address to manage (supports variable substitution, e.g. `{{public_ip}}`)
- **Comment** — Optional note attached to the IP entry
- **Action** — Add / Remove / Replace All

Per-task credentials work the same way as Cloudflare DNS tasks.

### Cloudflare Default Fields

In **Settings → Cloudflare DNS**, you can set global defaults that apply when a task leaves the corresponding field empty:

| Default | Purpose |
|---------|---------|
| **Zone ID** | Used when a Cloudflare task leaves its Zone ID field empty |
| **Record Name** | Used when a Cloudflare task leaves its Record Name field empty |
| **Proxied** | Used when a Cloudflare task leaves its Proxied field empty (e.g. `true` or `false`) |
| **TTL** | Used when a Cloudflare task leaves its TTL field empty (e.g. `60`) |

All four fields support **variable substitution**, so you can use `{{public_ip}}`, `{{ntfy_message}}`, etc. in any of them. This lets you create lightweight Cloudflare tasks that inherit most settings from global defaults while overriding specific values as needed.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `eframe` / `egui` | Native GUI |
| `serde` / `serde_json` | Configuration serialization |
| `chrono` | Date/time handling |
| `reqwest` | HTTP client |
| `aes-gcm` | Credential encryption |
| `pbkdf2` / `hmac` / `sha2` | Key derivation & hashing |
| `uuid` | Task identifiers |
| `parking_lot` | Synchronization primitives |
| `dirs` | System paths |

## Project Structure

```
src/
├── bin/
│   ├── gui.rs          # GUI entry point
│   └── service.rs      # Service entry point
├── app.rs              # egui application (task editor, settings, logs)
├── scheduler.rs        # Core scheduling & task execution engine
├── ntfy_listener.rs    # SSE listener for ntfy.sh subscriptions
├── smtp.rs             # Built-in SMTP server for email triggers
├── pushover.rs         # Pushover notification client
├── cloudflare.rs       # Cloudflare DNS API client
├── crypto.rs           # AES-256-GCM encryption utilities
├── config.rs           # Config file I/O
├── logger.rs           # Daily rotating log manager
└── task.rs             # Task, trigger, and action type definitions
```

## License

[Specify your license here]
