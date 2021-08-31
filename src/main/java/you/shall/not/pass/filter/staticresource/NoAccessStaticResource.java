package you.shall.not.pass.filter.staticresource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import you.shall.not.pass.domain.Access;

import javax.annotation.PostConstruct;
import java.util.List;

@Component
public class NoAccessStaticResource implements StaticResourceValidator {

    private static final Logger LOG = LoggerFactory.getLogger(NoAccessStaticResource.class);

    @Value("classpath:static/Level3/**")
    private Resource[] noAccessResources;

    @Autowired
    private StaticResourceService staticResourceService;

    private List<String> staticResources;

    @Override
    public boolean isApplicable(String requestUri) {
        boolean isApplicable = staticResources.stream().
                anyMatch(s -> s.equalsIgnoreCase(requestUri));
        LOG.info("matches {} resource: {}", requires(), isApplicable);
        return isApplicable;
    }

    @Override
    public Access requires() {
        return Access.NoAccessLevel;
    }

    @PostConstruct
    public void setList() {
        staticResources = staticResourceService.resolveStaticResources(noAccessResources);
        LOG.info("{} level resources: {}", requires(), staticResources);
    }

}
