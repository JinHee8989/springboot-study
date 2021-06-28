# 스프링 시큐리티란? 
1. 시큐리티가 필요한 이유 : 
웹사이트는 서비스를 제공하기 위한 리소스와 유저들의 개인정보를 가지고 있음. 리소스와 개인정보를 보호하기위해 두가지 보안 정책(인증과 권한)을 설정해야함 
    1)인증(Authentication) : 사이트에 접속하는 사용자가 누구인지에 시스템이 알아야함. 익명사용자(anonymous user)를 허용하는 경우도 있지만, 특정 리소스에 접근하거나 개인화된 사용성을 보장 받기 위해서는 반드시 로그인하는 과정이 필요함.
    로그인은 보통 [ID/PASSWORD를 입력]하고 로그인하는 경우와 [sns 사이트를 통해 인증을 대리]하는 경우가 있음.
                                   
       * UsernamePassword 인증
        - Session 관리
        - 토큰 관리 (sessionless) -> 최근에 여러 서버로 서비스하는 경우가 많아 세션을 분산하고 동기화해야하다보니 요즘은 세션리스로 토큰을 주로 사용하는 추세임 
       
       * Sns 로그인 (소셜 로그인) : 인증 위임
    
    2)권한(Authorization) : 사이트에 접속하는 사용자가 어떤 권한을 가지고 있는지 확인함. 
    권한은 특정 페이지에 접근하거나 특정 리소스에 접근할 수 있는 권한여부를 판단하는데 사용됨. 개발자는 권한이 있는 사용자에게만 페이지나 리소스 접근을 허용하도록 코딩해야 하는데, 이런 코드를 쉽게 작성할 수 있도록 프레임워크를 제공하는 것이 스프링 시큐리티 프레임워크(Spring Security Framework)임.
                                              
      * Secured : deprecated
      * PrePostAuthorize -> @Secured와 @PrePostAuthorize는 접근하려는 url에 annotation을 설정해 권한을 확인하는 방법
      * AOP

#스프링 시큐리티의 큰 그림 
1. 서블릿 컨테이너 : 톰캣과 같은 웹애플리케이션을 서블릿 컨테이너라고 부르며 기본적으로 필터와 서블릿으로 구성되어있다. 
   -서블릿 컨테이너 내에서 
    1)request가 threadlocal로 실행되어 들어옴
    2)필터를 차례로 거침 (필터는 체인처럼 엮여있기 때문에 '필터체인'이라고도 불림. 모든 request는 반드시 필터체인을 거쳐야 서블릿 서비스에 도착함)
    3)url에 따라 dispatchServlet에서 각각의 컨트롤러로 분기됨 (dispatchServlet은 여러개 설정도 가능)
    4)실행될 메소드를 찾아 request, response를 넘김
   
2.  스프링 시큐리티의 큰 그림 
    -그래서 스프링 시큐리티는 delegatingFilterProxy라는 필터를 만들어 메인 필터체인 사이에 끼워넣고, 그 아래 SecurityFilterChain그룹을 등록함 
    (본래의 메인 필터를 반드시 통과해야만 서블릿에 들어갈 수 있다는 단점을 보완하기 위해 필터체인 proxy를 둔 것)
    -SecurityConfig 클래스에서 상속받는 WebSecurityConfigurerAdapter가 필터체인을 구성하는 configuration 클래스임. 
    -이 필터체인은 반드시 한개 이상이고, url패턴에 따라 적용되는 필터체인을 다르게 할 수 있음.
    -web resource의 경우 패턴을 따르더라도 필터를 무시(ignore)하고 통과시켜주기도함 
    
3. 시큐리티 필터들 
    -각각의 필터는 단일 필터 단일 책임(?) 원칙 처럼, 각기 서로 다른 관심사를 해결함
        * HeaderWriterFilter : Http 해더를 검사한다. 써야 할 건 잘 써있는지, 필요한 해더를 더해줘야 할 건 없는가?
        * CorsFilter : 허가된 사이트나 클라이언트의 요청인가?
        * CsrfFilter : 내가 내보낸 리소스에서 올라온 요청인가?
        * LogoutFilter : 지금 로그아웃하겠다고 하는건가?
        * UsernamePasswordAuthenticationFilter : username / password 로 로그인을 하려고 하는가? 만약 로그인이면 여기서 처리하고 가야 할 페이지로 보내 줄께.
        * ConcurrentSessionFilter : 여거저기서 로그인 하는걸 허용할 것인가?
        * BearerTokenAuthenticationFilter : Authorization 해더에 Bearer 토큰이 오면 인증 처리 해줄께.
        * BasicAuthenticationFilter : Authorization 해더에 Basic 토큰을 주면 검사해서 인증처리 해줄께.
        * RequestCacheAwareFilter : 방금 요청한 request 이력이 다음에 필요할 수 있으니 캐시에 담아놓을께.
        * SecurityContextHolderAwareRequestFilter : 보안 관련 Servlet 3 스펙을 지원하기 위한 필터라고 한다.(?)
        * RememberMeAuthenticationFilter : 아직 Authentication 인증이 안된 경우라면 브라우저의 RememberMe 쿠키를 검사해서 인증 처리해줄께
        * AnonymousAuthenticationFilter : 아직도 인증이 안되었으면 너는 Anonymous 사용자야
        * SessionManagementFilter : 서버에서 지정한 세션정책을 검사할께.
        * ExcpetionTranslationFilter : 나 이후에 인증이나 권한 예외가 발생하면 내가 잡아서 처리해 줄께.
        * FilterSecurityInterceptor : 여기까지 살아서 왔다면 인증이 있다는 거니, 니가 들어가려고 하는 request 에 들어갈 자격이 있는지 그리고 리턴한 결과를 너에게 보내줘도 되는건지 마지막으로 내가 점검해 줄께.
    
    그 밖에... OAuth2 나 Saml2, Cas, X509 등에 관한 필터들도 있음.
    -필터는 넣거나 뺄 수 있고 순서 조절 가능 (이때 필터의 순서가 매우 critical 할 수 있기 때문에 기본 필터들은 그 순서가 어느정도 정해져 있다.)

#로그인 하기 
1.스프링 프레임워크에서 로그인이란? 
    - authenticated 가 true인 Authentication 객체를 SecurityContext 에 갖고 있는 상태. 단 Authentication이 AnonymousAuthenticationToken 만 아니면 됨.

2.인증(Authentication)의 기본 구조 
    - SecurityContextHolder : 인증보관함 보관소  
        - SecurityFilter 
        - SecurityContext : 인증 보관함
            - Authentication : 인증 보관함 안의 인증 
            - Principal(UserDetail), Credentials, details : 인증 대상
            - GrantedAuthority : 권한 
        - AuthenticationProvider : 인증 제공자 
            - ProviderManager : 인증 제공 관리자 
            - AuthenticationManager : 인증 관리자 
            
3.인증토큰(Authentication)을 제공하는 필터들
    * UsernamePasswordAuthenticationFilter : 폼 로그인 -> UsernamePasswordAuthenticationToken
    * RememberMeAuthenticationFilter : remember-me 쿠키 로그인 -> RememberMeAuthenticationToken
    * AnonymousAuthenticationFilter : 로그인하지 않았다는 것을 인증함 -> AnonymousAuthenticationToken
    * SecurityContextPersistenceFilter : 기존 로그인을 유지함(기본적으로 session 을 이용함)
    * BearerTokenAuthenticationFilter : JWT 로그인
    * BasicAuthenticationFilter : ajax 로그인 -> UsernamePasswordAuthenticationToken (로그인 화면이 없는 경우, 세션이 있는 경우에 많이 씀)
    * OAuth2LoginAuthenticationFilter : 소셜 로그인 -> OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken
    * OpenIDAuthenticationFilter : OpenID 로그인
    * Saml2WebSsoAuthenticationFilter : SAML2 로그인
 
    - Authentication 을 제공(Provide) 하는 인증제공자는 여러개가 동시에 존재할 수 있고, 인증 방식에 따라 ProviderManager 도 복수로 존재할 수 있음
    - Authentication 은 인터페이스로 아래와 같은 정보들을 갖고 있음
        *  Set<GrantedAuthority> authorities : 인증된 권한 정보
        *  principal : 인증 대상에 관한 정보. 주로 UserDetails 객체가 옴
        *  credentials : 인증 확인을 위한 정보. 주로 비밀번호가 오지만, 인증 후에는 보안을 위해 삭제함. (주로 아이디나 비번같은 input값이 들어옴)
        *  details : 그 밖에 필요한 정보. IP, 세션정보, 기타 인증요청에서 사용했던 정보들.
        *  boolean authenticated : 인증이 되었는지를 체크함.           
    
#폼 로그인
1. DefaultLoginPageGeneratingFilter
    -GET /login 을 처리
    -별도의 로그인 페이지 설정을 하지 않으면 제공되는 필터
    -기본 로그인 폼을 제공
    -OAuth2 / OpenID / Saml2 로그인과도 같이 사용할 수 있음.

2. UsernamePasswordAuthenticationFilter
    -POST /login 을 처리. processingUrl 을 변경하면 주소를 바꿀 수 있음.
    -form 인증을 처리해주는 필터로 스프링 시큐리티에서 가장 일반적으로 쓰임.
    -주요 설정 정보
        * filterProcessingUrl : 로그인을 처리해 줄 URL (POST)
        * username parameter : POST에 username에 대한 값을 넘겨줄 인자의 이름
        * password parameter : POST에 password에 대한 값을 넘겨줄 인자의 이름
        * 로그인 성공시 처리 방법
            -defaultSuccessUrl : alwaysUse 옵션 설정이 중요(주로 쓰임)
            -successHandler : defaultSuccessUrl과 같이 쓰면 defaultSuccessUrl이 안먹을 수도 있음 
        * 로그인 실패시 처리 방법
            -failureUrl
            -failureHandler
    -authenticationDetailSource : Authentication 객체의 details 에 들어갈 정보를 직접 만들어 줌. details는 리퀘스트안의 정보를 담아놓고(커스터마이징해서 담음) 원할 때 뽑아쓸 수 있음 
        * 예 :
        /** @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        		throws AuthenticationException {
        	if (this.postOnly && !request.getMethod().equals("POST")) {
        		throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        	}
        	String username = obtainUsername(request);
        	username = (username != null) ? username : "";
        	username = username.trim();
        	String password = obtainPassword(request);
        	password = (password != null) ? password : "";
        	UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        	// Allow subclasses to set the "details" property
        	setDetails(request, authRequest);
        	return this.getAuthenticationManager().authenticate(authRequest); //AuthenticationManager에게 인증처리권한을 넘김. AuthenticationManager는 AuthenticationProvider들에게 인증처리가 가능한 지 확인함 
        }
        **/
        
3. DefaultLogoutPageGeneratingFilter
    -GET /logout 을 처리
    -POST /logout 을 요청할 수 있는 UI 를 제공
    -DefaultLoginPageGeneratingFilter 를 사용하는 경우에 같이 제공됨.


4. LogoutFilter
    -POST /logout 을 처리. processiongUrl 을 변경하면 바꿀 수 있음.
    -로그 아웃을 처리
        * session, SecurityContext, csrf, 쿠키, remember-me 쿠키 등을 삭제처리 함.
        * (기본) 로그인 페이지로 redirect
    -LogoutHandler
        * void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
        * SecurityContextLogoutHandler : 세션과 SecurityContext 를 clear 함.
        * CookieClearingLogoutHandler : clear 대상이 된 쿠키들을 삭제함.
        * CsrfLogoutHandler : csrfTokenRepository 에서 csrf 토큰을 clear 함.
        * HeaderWriterLogoutHandler
        * RememberMeServices : remember-me 쿠키를 삭제함.
        * LogoutSuccessEventPublishingLogoutHandler : 로그아웃이 성공하면 이벤트를 발행함.
    -LogoutSuccessHandler
        * void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
        * throws IOException, ServletException;
        * SimpleUrlLogoutSuccessHandler