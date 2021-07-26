#include <cstdio>
#include <iostream>
#include <sstream> //stringstream保存cookie
#include <mutex>//互斥锁
#include <list>//链表保存session
#include <mysql/mysql.h>//mysql
#include <jsoncpp/json/json.h>//json
#include "mongoose.h"

using namespace std;

//设计im命名空间，防止函数和变量命名冲突，防止命名污染
namespace im
{
//定义宏用于连接mysql服务器的参数设置
#define MYSQL_HOST "127.0.0.1"
#define MYSQL_USER "root"
#define MYSQL_PASS ""
#define MYSQL_DB "im_system"
//
#define ONLINE "online"
#define OFFLINE "offline"
  //封装数据库用户访问类
  class TableUser
  {
  public:
    //构造函数
    //完成数据库操作的初始化
    //使用参数列表进行初始化，mysql句柄默认为NULL
    TableUser() : _mysql(NULL)
    {
      //初始化mysql句柄
      _mysql = mysql_init(NULL);
      if (_mysql == NULL)
      {
        printf("init mysql instance failed!\n");
        exit(-1);//初始化失败退出
      }
      //连接mysql服务器
      if (mysql_real_connect(_mysql, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB, 0, NULL, 0) == NULL)
      {
        printf("connect mysql server failed!\n");
        mysql_close(_mysql);
        exit(-1);
      }
      //设置当前客户端的字符集
      if (mysql_set_character_set(_mysql, "utf8") != 0)
      {
        printf("set client character failed:%s\n", mysql_error(_mysql));//打印错误信息
        mysql_close(_mysql);
        exit(-1);
      }
      //已经默认选择了数据库，不需要这个接口，切换时使用
      //选择操作的数据库
      //mysql_select_db(_mysql,MYSQL_DB);
    }
    
    //析构函数
    //完成数据库句柄的销毁
    ~TableUser()
    {
      if (_mysql)
        mysql_close(_mysql);
    }

    //用户信息的插入
    bool Insert(const string &name, const string &passwd)
    {
      //对密码进行MD5加密
#define INSERT_USER "insert tb_user value(null,'%s',MD5('%s'),'%s');"
      char tmp_sql[4096] = {0};
      //sprintf按照指定格式组织一个字符串放到tmp_sql缓冲区中
      sprintf(tmp_sql, INSERT_USER, name.c_str(), passwd.c_str(), OFFLINE);//默认为offline
      return QuerySql(tmp_sql);//执行语句
    }

    //用户信息的删除
    bool Delete(const string &name)
    {
#define DELETE_USER "delete from tb_user where name='%s';"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, DELETE_USER, name.c_str());
      return QuerySql(tmp_sql);
    }

    //用户状态的修改
    bool UpdateStatus(const string &name, const string &status)
    {
#define UPDATE_USER_STATU "update tb_user set status='%s' where name='%s';"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, UPDATE_USER_STATU, status.c_str(), name.c_str());
      return QuerySql(tmp_sql);
    }

    //用户密码的修改
    bool UpdatePasswd(const string &name, const string &passwd)
    {
      //对密码进行MD5加密
#define UPDATE_USER_PASS "update tb_user set passwd=MD5('%s') where name='%s';"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, UPDATE_USER_PASS, passwd.c_str(), name.c_str());
      return QuerySql(tmp_sql);
    }

    //查询单个用户信息，通过用户名和json接收单个用户信息
    bool SelectOne(const string &name, Json::Value *user)
    {
#define SELECT_USER_ONE "select id,passwd,status from tb_user where name='%s';"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, SELECT_USER_ONE, name.c_str());
      //执行语句和保存结果集并非原子操作，在多线程操作的时候可能会出问题
      _mutex.lock(); //加锁保护，将结果集保护起来，防止中间被打断
      if (QuerySql(tmp_sql) == false)
      {
        _mutex.unlock(); //失败解锁
        return false;
      }
      //执行成功，获取结果集到本地
      MYSQL_RES *res = mysql_store_result(_mysql);
      _mutex.unlock(); //正常解锁
      if (res == NULL)
      {
        printf("select one user store result failed:%s\n", mysql_error(_mysql));//打印错误原因
        return false;
      }
      //获取结果集中的行数
      int num_row = mysql_num_rows(res);
      if (num_row != 1)//!=1,因为获取的是单个用户，防止出现0的情况
      {
        printf("one user result count error!\n");
        mysql_free_result(res);
        return false;
      }
      for (int i = 0; i < num_row; i++)
      {
        //遍历结果集
        MYSQL_ROW row = mysql_fetch_row(res);
        //*的优先级比[]低，使用括号括起来
        (*user)["id"] = stoi(row[0]);
        (*user)["name"] = name.c_str();
        (*user)["passwd"] = row[1];
        (*user)["status"] = row[2];
      }
      mysql_free_result(res);
      return true;
    }

    //查询所有用户信息，通过json接收所有用户信息
    bool SelectAll(Json::Value *users)
    {
#define SELECT_ALL_USER "select id,name,passwd,status from tb_user;"
      _mutex.lock();
      if (QuerySql(SELECT_ALL_USER) == false)
      {
        _mutex.unlock();
        return false;
      }
      MYSQL_RES *res = mysql_store_result(_mysql);
      _mutex.unlock();
      if (res == NULL)
      {
        printf("select all user store result failed:%s\n", mysql_error(_mysql));
        return false;
      }
      int num_row = mysql_num_rows(res);
      for (int i = 0; i < num_row; i++)
      {
        MYSQL_ROW row = mysql_fetch_row(res);
        Json::Value user;
        user["id"] = stoi(row[0]);
        user["name"] = row[1];
        user["passwd"] = row[2];
        user["status"] = row[3];
        users->append(user); 
      }
      mysql_free_result(res);
      return true;
    }

    //用户信息的验证，用于登录
    bool VerifyUser(const string &name, const string &passwd)
    {
      //对密码进行MD5加密,MD5是sql中的一个聚合函数
#define VERIFY_USER "select *from tb_user where name='%s'and passwd=MD5('%s');"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, VERIFY_USER, name.c_str(), passwd.c_str());
      _mutex.lock();
      if (QuerySql(tmp_sql) == false)
      {
        _mutex.unlock();
        return false;
      }
      MYSQL_RES *res = mysql_store_result(_mysql);
      _mutex.unlock();
      if (res == NULL)
      {
        printf("verify user store result failed:%s\n", mysql_error(_mysql));
        return false;
      }
      int num_row = mysql_num_rows(res);
      if (num_row != 1)
      {
        printf("verify user failed!\n");
        return false;
      }
      mysql_free_result(res);
      return true;
    }

    //用户是否存在，用于注册时判断用户名是否被占用
    bool Exists(const string &name)
    {
#define EXISTS_USER "select *from tb_user where name='%s';"
      char tmp_sql[4096] = {0};
      sprintf(tmp_sql, EXISTS_USER, name.c_str());
      _mutex.lock();
      if (QuerySql(tmp_sql) == false)
      {
        _mutex.unlock();
        return false;
      }
      MYSQL_RES *res = mysql_store_result(_mysql);
      _mutex.unlock();
      if (res == NULL)
      {
        printf("exists user store result failed:%s\n", mysql_error(_mysql));
        return false;
      }
      int num_row = mysql_num_rows(res);
      if (num_row != 1)
      {
        printf("have no user!\n");
        mysql_free_result(res);
        return false;
      }
      mysql_free_result(res);
      return true;
    }

  private:
    //封装语句的执行，代码复用，设置为private
    bool QuerySql(const string &sql)
    {
      if (mysql_query(_mysql, sql.c_str()) != 0)
      {
        printf("query sql:[%s] failed:%s\n", sql.c_str(), mysql_error(_mysql));
        return false;
      } 
      return true;
    }

  private:
    MYSQL *_mysql;//数据库的操作句柄
    mutex _mutex;
  };

  struct session
  {
    string name;
    string status;
    uint64_t session_id;
    double login_time;
    double last_atime;
    struct mg_connection *conn;//哪个连接发送的消息
  };

  class IM
  {
  public:
    //析构函数
    ~IM()
    {
      ///关闭所有连接，并释放所有资源
      mg_mgr_free(&_mgr); 
    }

    //初始化
    static bool Init(const string &port = "9000")
    {
      //实例化一个对象
      _tb_user = new TableUser();
      //初始化句柄
      mg_mgr_init(&_mgr); 
      string addr = "0.0.0.0:";
      addr += port;
      //创建http监听连接
      //操作句柄 监听地址 回调函数 传入参数
      _lst_http = mg_http_listen(&_mgr, addr.c_str(), callback, &_mgr); 
      if (_lst_http == NULL)
      {
        cout<<"http listen failed!\n";
        return false;
      }
      return true;
    }

    //程序运行
    static bool Run()
    {
      while (1)
      {
        //轮询监听
        mg_mgr_poll(&_mgr, 1000); 
      }
      return true;
    }

  private:
    //分割字符串
    //Cookie：SESSION_ID-12312535; NAME=zhangsan; path=/
    static int Split(const string &str,const string &sep,vector<string>*list){
      //string::substr()，从pos位置开始截取指定长度字符串
      //string::find()，从pos位置开始找_s分隔符，返回所在位置
      int count=0;
      size_t pos=0,idx=0;//idx起始找寻位置
      while(1){
        pos=str.find(sep,idx);//从str字符串的idx位置开始找sep分隔符
        if(pos==string::npos){
          break;
        }
        list->push_back(str.substr(idx,pos-idx));
        idx=pos+sep.size();
        count++;
      }
      if(idx<str.size()){
        list->push_back(str.substr(idx));
        count++;
      }
      return count;
    }
    
    //获取cookie，通过分割字符串获取
    static bool GetCookie(const string &cookie,const string &key,string *val){
      vector<string>list;
      int count=Split(cookie,"; ",&list);
      for(auto s:list){
        vector<string>arry_cookie;
        Split(s,"=",&arry_cookie);
        if(arry_cookie[0]==key){
          *val=arry_cookie[1];
          return true;
        }
      }
      return false;;
    }
    
    //创建session
    static void CreateSession(struct session *s,struct mg_connection*c,const string &name){
      s->name=name;
      s->session_id=(uint64_t)(mg_time()*1000000);//session_id唯一
      s->login_time=mg_time();
      s->last_atime=mg_time();
      s->conn=c;
      return;
    }
    
    //删除session
    static void DeleteSession(struct mg_connection*c){
      auto it=_list.begin();
      for(;it!=_list.end();it++){
        if(it->conn==c){
          cout<<"delete session:"<<it->name<<endl;
          _list.erase(it);
          return;
        }
      }
      return;
    }
    
    //获取session-byconn
    static struct session *GetSessionByConn(struct mg_connection*c){
      auto it=_list.begin();
      for(;it!=_list.end();it++){
        if(it->conn==c){
          return&(*it);
        }
      return NULL;
      }
    }

    //获取session-byname
    static struct session *GetSessionByName(const string &name){
      auto it=_list.end();
      for(;it!=_list.end();it++){
        if(it->name==name){
          return&(*it);
        }
      return NULL;
      }
    }

    //注册
    static bool reg(struct mg_connection *c, struct mg_http_message *hm)
    {
      int status = 200;
      string header = "Content-Type:application/json\r\n";
      //从正文中获取提交的用户信息，json格式的字符串
      string body;
      body.assign(hm->body.ptr, hm->body.len);
      //解析进行反序列化得到用户名和密码
      Json::Value user;
      Json::Reader reader;
      bool ret = reader.parse(body, user);
      if (ret == false)
      {
        status = 400;
        mg_http_reply(c, status, header.c_str(), "{\"reason\":\"请求格式错误\"}");
        return false;
      }
      //判断这个用户名是否已经被占用
      ret = _tb_user->Exists(user["name"].asString());
      if (ret == true)
      {
        status = 400;
        mg_http_reply(c, status, header.c_str(), "{\"reason\":\"用户名被占用\"}");
        return false;
      }
      //将用户信息插入到数据库中
      ret = _tb_user->Insert(user["name"].asString(), user["passwd"].asString());
      if (ret == false){
        status = 500;
        mg_http_reply(c, status, header.c_str(), "{\"reason\":\"数据库访问错误\"}");
        return false;
      }
      mg_http_reply(c, status, header.c_str(), "{\"reason\":\"注册成功\"}");
      return true;
    }

    //登录
    static bool login(struct mg_connection *c, struct mg_http_message *hm)
    {
      int rsp_status = 200;
      string rsp_body = "{\"reason\":\"登录成功\"}";
      string rsp_header = "Content-Type:application/json\r\n";
      string req_body;
      req_body.assign(hm->body.ptr, hm->body.len);
      Json::Value user;
      Json::Reader reader;
      bool ret = reader.parse(req_body, user);
      if (ret == false)
      {
        rsp_status = 400;
        rsp_body = "{\"reason\":\"请求格式错误\"}";
        mg_http_reply(c, rsp_status, rsp_header.c_str(), rsp_body.c_str());
        return false;
      }
      //进行验证,验证用户名和密码
      ret = _tb_user->VerifyUser(user["name"].asString(), user["passwd"].asString());
      if (ret == false)
      {
        rsp_status = 403;
        rsp_body = "{\"reason\":\"用户名或密码错误\"}";
        mg_http_reply(c, rsp_status, rsp_header.c_str(), rsp_body.c_str());
        return false;
      }
      //用户登录成功之后创建session,以及设置客户端cookie,并且设置用户处于在线状态
      //#
      //设置用户处于在线状态
      ret=_tb_user->UpdateStatus(user["name"].asString(),ONLINE);
      if(ret==false){
        rsp_status = 500;
        rsp_body="{\"reason\":\"修改用户状态出错\"}";
        mg_http_reply(c, rsp_status, rsp_header.c_str(), rsp_body.c_str());
        return false;
      }
      //登录成功后创建session
      struct session s;
      CreateSession(&s,c,user["name"].asString());
      _list.push_back(s);
      stringstream cookie;
      cookie<<"Set-Cookie:SESSION_ID="<<s.session_id<<"; path=/\r\n";
      cookie<<"Set-Cookie:NAME="<<s.name<<"; path=/\r\n";
      rsp_header+=cookie.str();
      //#
      mg_http_reply(c, rsp_status, rsp_header.c_str(), rsp_body.c_str());
      return true;
    }

    //进行广播，遍历链表就能获取所有的连接
    static void Broadcast(const string &msg)
    {
      struct mg_connection *c;
      //遍历链表
      for (c = _mgr.conns; c != NULL; c = c->next)
      {
        //如果c是一个websocket连接，则调用mg_ws_send接口发送数据
        if (c->is_websocket){
          mg_ws_send(c, msg.c_str(), msg.size(), WEBSOCKET_OP_TEXT);
          //WEBSOCKET_OP_TEXT，选项标志位
        }
      }
      return;
    }

    //回调函数，设置为static函数，没有this指针，因为回调函数只有4个参数
    //回调函数：当前连接，触发事件，处理完毕的数据，传入参数
    static void callback(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
    {
      //http
      struct mg_http_message *hm = (struct mg_http_message *)ev_data;
      //websocket 
      struct mg_ws_message *wm = (struct mg_ws_message *)ev_data;    
      switch (ev)
      {
      case MG_EV_HTTP_MSG:
        //注册的提交表单数据请求
        if (mg_http_match_uri(hm, "/reg"))
        {
          //对注册封装一个函数reg
          reg(c, hm);
        }
        //登录的提交表单数据请求
        else if (mg_http_match_uri(hm, "/login"))
        {
          //对登录封装一个函数login
          login(c, hm);
        }
        //websocket的握手请求
        //在建立websocket聊天通道的时候，应该检测这个客户端是否已经登录
        //获取到请求头部中的cookie，通过cookie中的session或者name查找session
        else if (mg_http_match_uri(hm, "/websocket"))
        {
          //GetCookie(const string &cookie,const string &key,string *val)
          struct mg_str* cookie_str=mg_http_get_header(hm,"Cookie");//hm-头部信息
          if(cookie_str==NULL){
            //现在处于未登录状态，未登录用户
            //c++11,R"()",括号中的数据是一个原始字符串，没有特殊含义
            string body=R"({"reson":"未登录"})";
            string header="Content-Type:application/json\r\n";
            mg_http_reply(c,403,header.c_str(),body.c_str());
            return;
          }
          string tmp;
          tmp.assign(cookie_str->ptr,cookie_str->len);
          string name;
          GetCookie(tmp,"NAME",&name);
          string msg=name+" 加入聊天室...welcome!";
          Broadcast(msg);
          mg_ws_upgrade(c, hm, NULL);
        }
        //静态页面请求
        //除了登录界面，过来的时候，都应该检测一下Cookie，判断是否登录成功了
        //如果没有检测到session，则应该跳转到登录页面
        else
        {
          if (hm->uri.ptr!= "/login.html")
          {
            //获取一下cookie，根据name找session，没找到就意味着没有登录，
            //但是这里存在一个问题，login.html依赖的其他静态资源(图片，css代码)，
            //在没有登录成功的状态下，就获取不到这些资源

          }
          struct mg_http_serve_opts opts = {.root_dir = "./web_root"};
          mg_http_serve_dir(c, hm, &opts);
        }
        break;
      //收到一条聊天消息进行广播
      case MG_EV_WS_MSG:
      {
        string msg;
        msg.assign(wm->data.ptr, wm->data.len); //wm是已经解析好的websocket消息
        Broadcast(msg);
      }
        break;
      //连接断开
      //当一个连接断开的时候，删除当前用户session，设置用户为下线状态
      case MG_EV_CLOSE:
      //加个{}保证局部变量不会超出作用域
      {
        struct session *ss=GetSessionByConn(c);
        if(ss!=NULL){
          string msg=ss->name+"退出聊天室...";
          Broadcast(msg);
          _tb_user->UpdateStatus(ss->name,OFFLINE);
          DeleteSession(c);
        }
      }
        break;
      default:
        break;
    }
    return;
  }

  private: 
    string _addr; //监听地址信息  
    static TableUser *_tb_user;//定义一个数据库表访问类的指针
    static struct mg_mgr _mgr;//句柄              
    static struct mg_connection *_lst_http;//监听连接
    //使用链表保存session-需要频繁插入删除-不用map和vector-使用list快速插入删除 
    static list<struct session> _list;//cookie需要频繁插入删除，所以用链表     
};

//在类外进行static成员的初始化
TableUser* IM::_tb_user = NULL;
struct mg_mgr IM::_mgr;
struct mg_connection* IM::_lst_http = NULL;
list<struct session> IM::_list;

}
