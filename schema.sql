BEGIN TRANSACTION;
CREATE TABLE `tokens` (
	`token`	TEXT NOT NULL UNIQUE,
	`me`	TEXT NOT NULL,
	`client_id`	TEXT NOT NULL,
	`scope`	TEXT NOT NULL,
	`created`	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`revoked`	TEXT DEFAULT NULL,
	PRIMARY KEY(`token`)
);
CREATE TABLE `settings` (
	`name`	TEXT NOT NULL,
	`value`	TEXT NOT NULL,
	CONSTRAINT `setting` UNIQUE(`name`,`value`)
);
COMMIT;
