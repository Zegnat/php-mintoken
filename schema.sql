CREATE TABLE `tokens` (
	`token_id`	TEXT NOT NULL UNIQUE,
	`token_hash`	TEXT NOT NULL,
	`me`	TEXT NOT NULL,
	`client_id`	TEXT NOT NULL,
	`scope`	TEXT NOT NULL,
	`created`	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`revoked`	TEXT DEFAULT NULL,
	PRIMARY KEY(`token_id`)
);
CREATE TABLE `settings` (
	`name`	TEXT NOT NULL,
	`value`	TEXT NOT NULL,
	CONSTRAINT `setting` UNIQUE(`name`,`value`)
);
COMMIT;
