CREATE TABLE /*_*/wsoauth_mappings (
	wsoauth_user int unsigned NOT NULL UNIQUE,
	wsoauth_remote_name varchar(512) NOT NULL,
	PRIMARY KEY (wsoauth_remote_name),
	FOREIGN KEY (wsoauth_user) REFERENCES /*_*/wsoauth_users(wsoauth_user)
) /*$wgDBTableOptions*/;
