insert into users (username, password, enabled)
values ('user',
        'pass',
        true);
insert into users (username, password, enabled)
values ('admin',
        'pass',
        true);

-- Please Note Roles needs to be prefixed with `ROLE_` otherwise it doesn't work, but while authorizing the requests use without the prefix
insert into authorities (username, authority)
values ('user',
        'ROLE_USER');

insert into authorities (username, authority)
values ('admin',
        'ROLE_ADMIN');