#include <iostream>
#include <vector>
using namespace std;

class Solution {
public:
    void nextPermutation(vector<int>& nums) {
        int vector_size = nums.size();
        int start_index = 0;
        for(int i = vector_size - 1; i > 0; --i){
            if (nums[i] <= nums[i-1])continue;
            int left = i;
            int right = vector_size - 1;
            int middle = (left + right) / 2;
            while(left < right){
		cout<<left<<' '<<right<<endl;
                if(nums[middle] <= nums[i-1]){
                    right = middle - 1;
                    middle = (left + right) / 2;
                }else if(nums[middle > nums[i-1]){
                    left = middle + 1;
                    middle = (left + right) / 2;
                }
            }
            if(nums[middle] <= nums[i-1])middle--;
            int tmp = nums[middle];
            nums[middle] = nums[i-1];
            nums[i-1] = tmp;
            start_index = i;
            break;
            //return;
        }
        for(int i = 0;i < (vector_size - start_index)/2; ++i){
            int tmp = nums[vector_size - i - 1];
            nums[vector_size - i - 1] = nums[i + start_index];
            nums[i + start_index] = tmp;
        }
        return;
    }
};
int main(){
	Solution sol;
	vector<int>a = {0,0,4,2,1,0};
	sol.nextPermutation(a);
	for (int i = 0;i<a.size();++i)
		std::cout << a[i] << std::endl;
}
