package com.github.protocolfuzzing.zigbeefuzzer.symbols;

import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.xml.AlphabetPojoXml;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@XmlRootElement(name = "alphabet")
@XmlAccessorType(XmlAccessType.FIELD)
public class AlphabetPojoXmlZigbee extends AlphabetPojoXml<InputZigbee> {
    @XmlElements(value = {
        @XmlElement(type = InputPojoXmlZigbee.class, name = "InputZigbee")
    })
    private List<InputPojoXmlZigbee> xmlInputs;

    public AlphabetPojoXmlZigbee() {
        xmlInputs = new ArrayList<>();
    }

    public List<InputZigbee> getInputs() {
        List<InputZigbee> allInputs = xmlInputs.stream().map(xmlInput -> new InputZigbee(xmlInput.name)).collect(Collectors.toList());
        return allInputs;
    }

    public static class InputPojoXmlZigbee {
        @XmlAttribute(name = "name", required = true)
        private String name;
    }
}
