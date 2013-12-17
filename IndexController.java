/*
 * Copyright (c) 2013 www.jd.com All rights reserved.
 * 本软件源代码版权归京东成都云平台所有,未经许可不得任意复制与传播.
 */
package com.jd.uwp.web;

import java.util.List;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import com.jd.uwp.common.Constants;
import com.jd.uwp.common.spring.secret.AuthType;
import com.jd.uwp.common.spring.secret.Authentication;
import com.jd.uwp.common.tools.CookieUtils;
import com.jd.uwp.common.tools.EncryptUtils;
import com.jd.uwp.common.tools.MD5Utils;
import com.jd.uwp.common.tools.ValidateUtils;
import com.jd.uwp.domain.Menu;
import com.jd.uwp.domain.User;
import com.jd.uwp.service.MenuService;
import com.jd.uwp.service.UserService;
import com.jd.uwp.web.base.BaseWebSite;

/**
 * 首页
 * @author cfish
 * @since 2013-09-09
 */
@Controller("indexController")
@RequestMapping(value = "/", method = {RequestMethod.GET,RequestMethod.POST})
public class IndexController extends BaseWebSite {
	@Resource private UserService userService;
	@Resource private MenuService menuService;

	@RequestMapping(method={RequestMethod.GET,RequestMethod.POST})
    @Authentication(type=AuthType.NONE)
    public ModelAndView login(String userName,String password,String id) {
		Result result = new Result();
        result.addDefaultModel("returnUrl", id); 
        if(getLoginUser() != null) {
            sendRedirect(StringUtils.isEmpty(id) ? "welcome/" : "welcome?id=" + id);
            return null;//已经有用户登录成功啦
        }
        //系统登录界面包含用户名密码
        if(StringUtils.isNotEmpty(userName) && StringUtils.isNotEmpty(password)) {
            boolean res = userService.verify(userName, password);
            if(res) {
                String loginKey = EncryptUtils.desEncode(CookieUtils.randomValue(userName));
                CookieUtils.addCookie(getResponse(), Constants.LOGIN_USER_COOKIE_NAME, loginKey);
                sendRedirect(StringUtils.isEmpty(id) ? "welcome/" : "welcome?id=" + id);
                return null;
            } 
        }
        //判断有无登录ERP系统
        if(parseDotnetTicket(getRequest())) {
            sendRedirect(StringUtils.isEmpty(id) ? "welcome/" : "welcome?id=" + id);
            return null;
        }
		return loginPage(result);
	}
	
	@RequestMapping("/main")
	@Authentication(type=AuthType.PUBLIC)
    public ModelAndView main(){
        return toResult("main", null);
    }
	
	@RequestMapping("/help")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help(){
		return toResult("help", null);
	}
	
	@RequestMapping("/help2")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help2(){
		return toResult("help2", null);
	}
	@RequestMapping("/help3")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help3(){
		return toResult("help3", null);
	}
	@RequestMapping("/help4")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help4(){
		return toResult("help4", null);
	}
	@RequestMapping("/help5")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help5(){
		return toResult("help5", null);
	}
	@RequestMapping("/help6")
	@Authentication(type=AuthType.NONE)
	public ModelAndView help6(){
		return toResult("help6", null);
	}
	
	@RequestMapping(value="welcome",method={RequestMethod.GET,RequestMethod.POST})
    @Authentication(type=AuthType.PUBLIC)
	public ModelAndView welcome(String id){
		Result result = new Result();
		User user = getLoginUser();
		Menu queryMenu = new Menu();
		if(!user.isAdmin()) {
			queryMenu.setAuth(0);
		}
	    List<Menu> menuList = menuService.selectEntryList(queryMenu);
        result.addDefaultModel("menuList", menuList);
        
        String token = MD5Utils.MD5(user.getName() + Constants.getSystemCfg("uwp.md5.key"));
        result.addDefaultModel("token", token);
        
        result.addDefaultModel("requestid", id);
        return toResult("index", result);
	}
	
	@RequestMapping(value="logout")
    @Authentication(type=AuthType.NONE)
    public ModelAndView logout() {
        HttpServletRequest request = getRequest();
        HttpServletResponse response = getResponse();
        String key = CookieUtils.getCookieValue(request, Constants.LOGIN_USER_COOKIE_NAME);
        User user = redisService.userLogout(key);
        if(user != null) {
            LOGGER.info("用户 {}[{}] 登出",user.getName(),user.getRealName());
        }
        CookieUtils.delAllCookie(request, response);
        String keys = Constants.getSystemCfg("hrm.auth.cookie.name");
        CookieUtils.delCookie(response, ".jd.com", keys);
        Result result = new Result();
        return loginPage(result);
    }
	
	private ModelAndView loginPage(Result result) {
        HttpServletRequest request = getRequest();
        boolean ssoSupport = Constants.getBooleanCfg("login.sso.support",true);
        boolean localLogin = !ssoSupport || "false".equals(request.getParameter("sso")) || ValidateUtils.checkIP(request.getServerName());
        String returnUrl = CookieUtils.getRequestURL(request);
        System.out.println("testbyHelloKitty");
        if(!localLogin) {
            return null;
        }
        return toResultSkipLayout("login", result);
    }
	
	public static void main(String[] args) {
		System.out.println("liliang");
	}
}
