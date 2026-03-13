CREATE DATABASE IF NOT EXISTS user_svc;

CREATE USER IF NOT EXISTS 'user_svc'@'%' IDENTIFIED BY 'user_svc_pass';
GRANT ALL PRIVILEGES ON user_svc.* TO 'user_svc'@'%';

CREATE DATABASE IF NOT EXISTS post_svc;

CREATE USER IF NOT EXISTS 'post_svc'@'%' IDENTIFIED BY 'post_svc_pass';
GRANT ALL PRIVILEGES ON post_svc.* TO 'post_svc'@'%';

FLUSH PRIVILEGES;
