drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  title text not null,
  author text not null,
  category text,
  'text' text not null
);

drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  pw_hash text not null
);