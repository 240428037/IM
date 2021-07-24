create database if not exists im_system;

use im_system;

create table if not exists tb_user(
  id int primary key auto_increment,
  name varchar(32) not null unique comment '用户名',
  passwd varchar(32) not null comment '密码',
  status varchar(8) not null comment '状态信息-offline/online'
);
 