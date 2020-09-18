package org.optaweb.vehiclerouting.plugin.persistence.config;

import java.util.List;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;


import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;




//@Component
@Configuration

@EnableWebSocketMessageBroker

@Order(Ordered.HIGHEST_PRECEDENCE + 99)
public class JwtRequestFilter /*extends OncePerRequestFilter*/ implements WebSocketMessageBrokerConfigurer {
    /*
    @Autowired
    private JwtPlannerDetailsService jwtUserDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    */
    private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);
    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {

        registration.interceptors(new ChannelInterceptor() {

            @Override

            public Message<?> preSend(Message<?> message, MessageChannel channel) {

                StompHeaderAccessor accessor =

                        MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
                        if (StompCommand.CONNECT.equals(accessor.getCommand())) {

                            List<String> authorization = accessor.getNativeHeader("Authorization");
                            

                            logger.debug("X-Authorization: {}", authorization);

                            //String accessToken = authorization.get(0).split(" ")[1];
                            /*
                            Jwt jwt = jwtDecoder.decode(accessToken);

                            JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

                            Authentication authentication = converter.convert(jwt);

                            accessor.setUser(authentication);
                            */
        
                           
        
                        }
        
                        
              
                return message;

            }

        });

    }
    /*
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String requestTokenHeader = request.getHeader("Authorization");
        
        final String test = request.getHeader("X-Authorization");
        final String test2 = request.getHeader("token");
        logger.info(test);
        logger.info(requestTokenHeader);
        logger.info(test2);
        String username = null;
        String jwtToken = null;
        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }
        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
            // if token is valid configure Spring Security to manually set
            // authentication
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
    */
}