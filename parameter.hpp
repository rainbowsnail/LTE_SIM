#ifndef PARAMETERS_HPP_
#define PARAMETERS_HPP_

/// Parameter: flow duration(s)
constexpr int DURATION = 150;

/// Parameter: window to calculate minimum RTT
constexpr int RTT_WINDOW = 10;
constexpr float MAX_FLOAT_NUM = 1000000000;
/// Parameter: 
constexpr int MAX_FLOW_DURATION = 150;

/// Patameter: granularity: duration of each time slot 
/// to calculate goodput and loss rate 
constexpr float GRANULARITY = 0.01; // i.e. 10 ms = 0.01 s ; 

#endif
