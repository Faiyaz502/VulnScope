alter table users add column mfa_enabled boolean not null default false;
alter table users add column mfa_secret varchar(512);

create table password_reset_tokens (
    id uuid primary key,
    user_id uuid not null references users(id),
    token_hash varchar(64) not null unique,
    expires_at timestamp with time zone not null,
    used_at timestamp with time zone
);
create index idx_password_reset_token_user on password_reset_tokens(user_id);
create index idx_password_reset_token_expiry on password_reset_tokens(expires_at);
