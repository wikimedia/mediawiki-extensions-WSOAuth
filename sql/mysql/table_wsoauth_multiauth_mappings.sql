CREATE TABLE /*_*/wsoauth_multiauth_mappings (
	wsoauth_user int unsigned NOT NULL,
	wsoauth_remote_name varchar(512) NOT NULL,
	wsoauth_provider_id varchar(255) NOT NULL,
	PRIMARY KEY (wsoauth_remote_name, wsoauth_provider_id)
) /*$wgDBTableOptions*/;
