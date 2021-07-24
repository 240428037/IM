#include "im.hpp"

// void sql_test()
// {
//   //实例化一个user对象
//   im::TableUser user;

//   //测试用户信息的插入
//   user.Insert("lisi","111111");
//   user.Insert("zhangsan","111111");

//   //测试修改密码
//   user.UpdatePasswd("lisi","111112");//1

//   //测试验证用户信息
//   cout<<user.VerifyUser("zhangsan","111111")<<endl;//1

//   //测试验证用户是否存在
//   cout<<user.Exists("wangwu")<<endl;//have no user;0;
//   cout<<user.Exists("lisi")<<endl;//1
 
//   //测试查询单个用户信息
//   Json::Value val;
//   user.SelectOne("zhangsan",&val);
//   Json::StyledWriter writer;
//   cout<<writer.write(val)<<endl;

//   //测试查询所有用户信息
//   Json::Value val;
//   user.SelectAll(&val);
//   Json::StyledWriter writer; 
//   cout<<writer.write(val)<<endl;

//   //测试用户信息的删除
//   user.Delete("zhangsan");
// }

int main(int argc, char *argv[])
{
  // sql_test();
  im::IM im_server;//实例化一个对象
  im_server.Init();//初始化
  im_server.Run();//运行
  return 0;
}
