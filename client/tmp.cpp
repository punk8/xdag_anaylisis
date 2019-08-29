#include <iostream>
 
using namespace std;

class Payroll
{
    public:
        double payperhour = 10.0;   // 
        int workhours;  // 
        double payment;   // 
        double getPayment(int hours){
            payment = hours*payperhour;
            workhours = hours;
            return payment;
        }

        void setPayperhour(double perhour){
            payperhour = perhour;
        }
    
};

int main( )
{
    Payroll worker[10];
    
    for(Payroll iworker : worker){
        int worktime = 0;
        cout << "请输入您的工作时长： ";
        cin >> worktime;
        if(worktime<0||worktime>60){
            break;
        }
        cout<<"您的工资："<<iworker.getPayment(worktime);
    }

   
   
   return 0;
}