#ifndef PARAMETERS_HPP_
#define PARAMETERS_HPP_

/// Parameter: flow duration(s)
constexpr int DURATION = 150;

/// Parameter: window to calculate minimum RTT
constexpr int RTT_WINDOW = 10;
constexpr float MAX_FLOAT_NUM = 10000000;
/// Parameter: 
constexpr int MAX_FLOW_DURATION = 50;

/// Patameter: granularity: duration of each time slot 
/// to calculate goodput and loss rate 
//constexpr double GRANULARITY = 0.010; // i.e. 10 ms = 0.01 s ; 
constexpr int GRANU_SCALE = 100;
constexpr int MS_IN_S = 1000;

#endif
