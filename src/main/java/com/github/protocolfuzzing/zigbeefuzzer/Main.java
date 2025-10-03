package com.github.protocolfuzzing.zigbeefuzzer;

import com.github.protocolfuzzing.zigbeefuzzer.symbols.InputZigbee;
import com.github.protocolfuzzing.zigbeefuzzer.symbols.OutputZigbee;
import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.statistics.MealyMachineWrapper;
import com.github.protocolfuzzing.protocolstatefuzzer.entrypoints.CommandLineParser;

public class Main {
    public static void main(String[] args) {
        // Multibuilder implements all necessary builders
        MultiBuilder mb = new MultiBuilder();

        // single parentLogger, if Main resides in the outermost package
        String[] parentLoggers = {Main.class.getPackageName()};

        CommandLineParser<MealyMachineWrapper<InputZigbee, OutputZigbee>> commandLineParser = new CommandLineParser<MealyMachineWrapper<InputZigbee, OutputZigbee>>(mb, mb, mb, mb);
        commandLineParser.setExternalParentLoggers(parentLoggers);

        commandLineParser.parse(args, true);
    }
}
