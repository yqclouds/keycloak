package com.yqboots.fss.core.convert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * A Spring Converter for converting from String to NIO Path.
 * <p/>
 * <p>Used to convert file path related properties.</p>
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@ConfigurationPropertiesBinding
public class StringToPathConverter implements Converter<String, Path> {
    private static final Logger LOG = LoggerFactory.getLogger(StringToPathConverter.class);

    /**
     * Convert the source object of type {@code S} to target type {@code T}.
     *
     * @param source the source object to convert, which must be an instance of {@code S} (never {@code null})
     * @return the converted object, which must be an instance of {@code T} (potentially {@code null})
     * @throws IllegalArgumentException if the source cannot be converted to the desired target type
     */
    @Override
    public Path convert(final String source) {
        Path result = Paths.get(source.replace("\\", File.separator));
        if (!Files.exists(result)) {
            LOG.error("Path not found [{}]", result);
        }

        return result;
    }
}
