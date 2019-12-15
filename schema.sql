
drop table if exists cuser;
create table cuser (
  username TEXT UNIQUE,
  password TEXT,
  focus TEXT,
  email TEXT,
  msgedUser TEXT,
  id SERIAL PRIMARY KEY,
  message TEXT
);

drop table if exists authors;
create table authors (
  author_id INTEGER,
  authorName TEXT,
  title TEXT,
  github TEXT,
  body TEXT,
  skills TEXT,
  var1 TEXT,
  var2 TEXT,
  var3 TEXT,
  key CHAR,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  id SERIAL PRIMARY KEY,
  FOREIGN KEY (author_id) REFERENCES cuser (id)
);

drop table if exists book;
create table book (
  author_id INTEGER,
  authorName TEXT,
  recipient_id TEXT,
  messag TEXT,
  id SERIAL PRIMARY KEY,
  FOREIGN KEY (author_id) REFERENCES cuser (id)
);
