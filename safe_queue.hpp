#ifndef SAFE_QUEUE
#define SAFE_QUEUE

#include <queue>
#include <mutex>
#include <condition_variable>
#include <iostream>
// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
  SafeQueue(void)
    : q()
    , m()
    , c()
  {}

  ~SafeQueue(void)
  {}

  void clear(){
    std::lock_guard<std::mutex> lock(m);
    while (!q.empty()) q.pop();
  }
  bool is_empty(){
    std::lock_guard<std::mutex> lock(m);
    if(q.empty())return true;
    return false;
  }
  // Add an element to the queue.
  void enqueue(T t)
  {
    //std::cout << "going to enqueue"<<std::endl;
    {
      std::lock_guard<std::mutex> lock(m);
      q.push(t);
    }
    c.notify_one();
    //std::cout << "finish enqueue"<<std::endl;
  }

  // Get the "front"-element.
  // If the queue is empty, wait till a element is avaiable.
  T dequeue(void)
  {
    //std::cout << "going to dequeue"<<std::endl;
    std::unique_lock<std::mutex> lock(m);
    c.wait(lock,[this]() { return !q.empty(); });  // 4.front 和 pop_front时独占锁
    T val=std::move(q.front());
    q.pop();
    /*
    while(q.empty())
    {
      std::cout << "c.wait(lock)"<<std::endl;
      // release lock as long as the wait and reaquire it afterwards.
      c.wait(lock);
    }
    T val = q.front();
    q.pop();*/
    //std::cout << "dequeue success"<<std::endl;
    
    return val;
  }

private:
  std::queue<T> q;
  mutable std::mutex m;
  std::condition_variable c;
};

#endif