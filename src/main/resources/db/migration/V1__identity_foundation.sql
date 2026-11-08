create table users (
    id uuid primary key,
    email varchar(320) not null unique,
    password_hash varchar(255) not null,
    display_name varchar(120) not null,
    enabled boolean not null default true,
    created_at timestamp with time zone not null
);

create table organizations (
    id uuid primary key,
    name varchar(160) not null,
    created_at timestamp with time zone not null
);

create table organization_memberships (
    id uuid primary key,
    organization_id uuid not null references organizations(id),
    user_id uuid not null references users(id),
    role varchar(32) not null,
    created_at timestamp with time zone not null,
    constraint uq_membership_organization_user unique (organization_id, user_id)
);

create index idx_membership_user on organization_memberships(user_id);

create table auth_sessions (
    id uuid primary key,
    user_id uuid not null references users(id),
    token_hash varchar(64) not null unique,
    created_at timestamp with time zone not null,
    expires_at timestamp with time zone not null,
    last_seen_at timestamp with time zone not null,
    revoked_at timestamp with time zone
);

create index idx_auth_session_user on auth_sessions(user_id);
create index idx_auth_session_expiry on auth_sessions(expires_at);

create table audit_events (
    id uuid primary key,
    organization_id uuid references organizations(id),
    actor_user_id uuid references users(id),
    event_type varchar(80) not null,
    occurred_at timestamp with time zone not null,
    ip_address varchar(45),
    metadata_json text
);

create index idx_audit_organization_time on audit_events(organization_id, occurred_at);
