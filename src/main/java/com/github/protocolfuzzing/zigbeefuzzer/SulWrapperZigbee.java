// package com.github.protocolfuzzing.zigbeefuzzer;
//
// import java.time.Duration;
// import java.util.concurrent.atomic.AtomicLong;
//
// import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSul;
// import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulWrapper;
// import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
// import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
//
// import de.learnlib.filter.statistic.Counter;
//
// public class SulWrapperZigbee implements SulWrapper<InputZigbee, OutputZigbee, ExecutionContextZigbee>{
//     private AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> sul;
//     private final ExecutionContextZigbee context;
//
//     private final Counter inputCounter = new Counter("inputCounter", 0);
//     private final Counter testCounter = new Counter();
//     private Long testLimit = null;
//     private Duration timeLimit = null;
//     private String loggingWrapper = null;
//
//     public SulWrapperZigbee(AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> sul, ExecutionContextZigbee context){
//         this.sul = sul;
//         this.context = context;
//     }
//
//     @Override
//     public AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> sul() {
//         return sul;
//     }
//
//     @Override
//     public ExecutionContextZigbee context() {
//         return context;
//     }
//
//
//     @Override
//     public SulWrapper<InputZigbee, OutputZigbee, ExecutionContextZigbee> 
//     wrap(AbstractSul<InputZigbee, OutputZigbee, ExecutionContextZigbee> newSul){
//         this.sul = newSul;
//         return this;
//     }
//
//     @Override
//     public Counter getInputCounter() { 
//         return inputCounter; 
//     }
//     
//     @Override
//     public AtomicLong getTestCounter() {
//         return testCounter;
//     }
//
//     @Override
//     public void setTestLimit(Long limit) {
//         this.testLimit = limit;
//     }
//
//     @Override
//     public void setTimeLimit(Duration limit) {
//         this.timeLimit = limit;
//     }
//
//     @Override
//     public void setLoggingWrapper(String loggingWrapper) {
//         this.testLimit = loggingWrapper;
//     }
//
// }
