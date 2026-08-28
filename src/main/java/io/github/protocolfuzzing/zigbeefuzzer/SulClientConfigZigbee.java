package io.github.protocolfuzzing.zigbeefuzzer;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULAdapterConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULClientConfigStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;

public class SulClientConfigZigbee extends SULClientConfigStandard {
    private Integer port = null;
    private Long clientWait = 50L;

    public SulClientConfigZigbee(MapperConfig mapperConfig, SULAdapterConfig sulAdapterConfig) {
        super(mapperConfig, sulAdapterConfig);
    }

    @Override
    public Integer getPort() {
        return port;
    }

    @Override
    public void setPort(Integer port) {
        this.port = port;
    }

    @Override
    public Long getClientWait() {
        return clientWait;
    }

    @Override
    public SULConfig cloneWithThreadId(int threadId) {
        SULAdapterConfig newAdapterConfig = this.sulAdapterConfig;
        MapperConfig newMapperConfig = this.mapperConfig;
        return new SulClientConfigZigbee(newMapperConfig, newAdapterConfig);
    }
}
