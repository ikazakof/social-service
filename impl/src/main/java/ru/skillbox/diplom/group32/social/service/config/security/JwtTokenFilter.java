package ru.skillbox.diplom.group32.social.service.config.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.info("Start jwt JwtTokenFilter");
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);
        log.info("Token = " + token);

        if (token != null && !token.equals("")) {
            if (jwtTokenProvider.validateToken(token)) {
                log.info("JwtTokenFilter: Check token = " + token);
                Authentication auth = jwtTokenProvider.getAuthentication(token);

                if (auth != null) {
                    log.info("JwtTokenFilter: Check auth = " + auth.getName());
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } else {
                log.info("JwtTokenFilter: Token expired, send status 401");
                HttpServletResponse res = (HttpServletResponse) response;
                res.sendError(401, "Jwt expired");
            }
        }
        filterChain.doFilter(request, response);
    }
}
