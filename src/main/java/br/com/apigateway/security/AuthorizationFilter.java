package br.com.apigateway.security;

import io.jsonwebtoken.Jwts;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import sun.plugin.liveconnect.SecurityContextHelper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class AuthorizationFilter extends BasicAuthenticationFilter {


    public AuthorizationFilter(AuthenticationManager authenticationManager, Environment environment) {
        super(authenticationManager);
        setEnvironment(environment);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

       String authorizationHeader = request.getHeader(getEnvironment().getProperty("authorization.token.header.name"));
       if(authorizationHeader == null  || !authorizationHeader.startsWith(getEnvironment().getProperty("authorization.token.header.prefix"))){
           chain.doFilter(request, response);
           return;
       }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest httpServletRequest){
        String authorizationHeader = httpServletRequest.getHeader(getEnvironment().getProperty("authorization.token.header.name"));

        if(authorizationHeader == null){
            return null;
        }

        String token = authorizationHeader.replace(getEnvironment().getProperty("authorization.token.header.prefix"), "");

        String userId = Jwts.parser()
                .setSigningKey(getEnvironment().getProperty("token.secret"))
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        if(userId == null){
            return null;
        }
        return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());

    }
}
