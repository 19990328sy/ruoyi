package com.ruoyi.web.controller.system;

import java.time.chrono.IsoChronology;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletResponse;

import com.ruoyi.framework.web.domain.server.Sys;
import com.sun.jna.platform.unix.solaris.LibKstat;
import com.sun.org.apache.regexp.internal.RE;
import org.apache.commons.lang3.ArrayUtils;
import org.aspectj.weaver.loadtime.Aj;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import com.ruoyi.common.annotation.Log;
import com.ruoyi.common.constant.UserConstants;
import com.ruoyi.common.core.controller.BaseController;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysRole;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.page.TableDataInfo;
import com.ruoyi.common.enums.BusinessType;
import com.ruoyi.common.utils.SecurityUtils;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.common.utils.poi.ExcelUtil;
import com.ruoyi.system.service.ISysPostService;
import com.ruoyi.system.service.ISysRoleService;
import com.ruoyi.system.service.ISysUserService;
import oshi.driver.mac.net.NetStat;

/**
 * 用户信息
 *
 * @author ruoyi
 */
@RestController
@RequestMapping("/system/user")
public class SysUserController extends BaseController {
    //用户
    @Autowired
    private ISysUserService userService;

    //角色
    @Autowired
    private ISysRoleService roleService;

    //部门
    @Autowired
    private ISysPostService postService;

    /**
     * 获取用户列表
     */
    @PreAuthorize("@ss.hasPermi('system:user:list')")
    @GetMapping("/list")
    public TableDataInfo list(SysUser user) {
        /*startPage();
        List<SysUser> list = userService.selectUserList(user);
        return getDataTable(list);*/
        startPage ();
        List<SysUser> list = userService.selectUserList ( user );
        //返回调用帮助类BaseController里面的写的返回成功的方法
        return getDataTable ( list );
    }

    /***
     *功能描述
     * @author shaoyu
     * @date 2022/3/29
     * @param response
     * @param user
     * @return void
     * @Description :这个是导入文件 即文件上传
     */

    @Log(title = "用户管理", businessType = BusinessType.EXPORT)
    @PreAuthorize("@ss.hasPermi('system:user:export')")
    @PostMapping("/export")
    public void export(HttpServletResponse response, SysUser user) {
        /*List<SysUser> list = userService.selectUserList(user);
        ExcelUtil<SysUser> util = new ExcelUtil<SysUser>(SysUser.class);
        util.exportExcel(response, list, "用户数据");*/
        List<SysUser> list = userService.selectUserList ( user );
        ExcelUtil<SysUser> util = new ExcelUtil<> ( SysUser.class );
        util.exportExcel ( response, list, "用户的数据" );
    }

    @Log(title = "用户管理", businessType = BusinessType.IMPORT)
    @PreAuthorize("@ss.hasPermi('system:user:import')")
    @PostMapping("/importData")
    public AjaxResult importData(MultipartFile file, boolean updateSupport) throws Exception {
        /*ExcelUtil<SysUser> util = new ExcelUtil<SysUser>(SysUser.class);
        List<SysUser> userList = util.importExcel(file.getInputStream());
        String operName = getUsername();
        String message = userService.importUser(userList, updateSupport, operName);
        return AjaxResult.success(message);*/
        ExcelUtil<SysUser> util = new ExcelUtil<> ( SysUser.class );
        List<SysUser> userList = util.importExcel ( file.getInputStream () );
        String operName = getUsername ();
        String message = userService.importUser ( userList, updateSupport, operName );
        return AjaxResult.success ( message );
    }

    //导出的模板
    @PostMapping("/importTemplate")
    public void importTemplate(HttpServletResponse response) {
        /*ExcelUtil<SysUser> util = new ExcelUtil<SysUser>(SysUser.class);
        util.importTemplateExcel(response, "用户数据");*/
        ExcelUtil<SysUser> util = new ExcelUtil<> ( SysUser.class );
        util.importTemplateExcel ( response, "用户的数据" );
    }

    /**
     * 根据用户编号获取详细信息
     */
    @PreAuthorize("@ss.hasPermi('system:user:query')")
    @GetMapping(value = {"/", "/{userId}"})
    public AjaxResult getInfo(@PathVariable(value = "userId", required = false) Long userId) {
        /*userService.checkUserDataScope(userId);
        AjaxResult ajax = AjaxResult.success();
        List<SysRole> roles = roleService.selectRoleAll();
        ajax.put("roles", SysUser.isAdmin(userId) ? roles : roles.stream().filter(r -> !r.isAdmin()).collect(Collectors.toList()));
        ajax.put("posts", postService.selectPostAll());
        if (StringUtils.isNotNull(userId))
        {
            SysUser sysUser = userService.selectUserById(userId);
            ajax.put(AjaxResult.DATA_TAG, sysUser);
            ajax.put("postIds", postService.selectPostListByUserId(userId));
            ajax.put("roleIds", sysUser.getRoles().stream().map(SysRole::getRoleId).collect(Collectors.toList()));
        }
        return ajax;*/

        userService.checkUserDataScope ( userId );
        AjaxResult ajax = AjaxResult.success ();
        List<SysRole> roles = roleService.selectRoleAll ();
        ajax.put ( "roles", SysUser.isAdmin ( userId ) ? roles : roles.stream ().filter ( r -> !r.isAdmin () ).collect ( Collectors.toList () ) );
        ajax.put ( "posts", postService.selectPostAll () );
        if ( StringUtils.isNotNull ( userId ) ) {
            SysUser sysUser = userService.selectUserById ( userId );
            ajax.put ( AjaxResult.DATA_TAG, sysUser );
            ajax.put ( "postIds", postService.selectPostListByUserId ( userId ) );
            ajax.put ( "roleIds", sysUser.getRoles ().stream ().map ( SysRole::getRoleId ).collect ( Collectors.toList () ) );
        }
        return ajax;
    }

    /**
     * 新增用户
     */
    @PreAuthorize("@ss.hasPermi('system:user:add')")
    @Log(title = "用户管理", businessType = BusinessType.INSERT)
    @PostMapping
    public AjaxResult add(@Validated @RequestBody SysUser user) {
        /*if ( UserConstants.NOT_UNIQUE.equals ( userService.checkUserNameUnique ( user.getUserName () ) ) ) {
            return AjaxResult.error ( "新增用户'" + user.getUserName () + "'失败，登录账号已存在" );
        } else if ( StringUtils.isNotEmpty ( user.getPhonenumber () )
                && UserConstants.NOT_UNIQUE.equals ( userService.checkPhoneUnique ( user ) ) ) {
            return AjaxResult.error ( "新增用户'" + user.getUserName () + "'失败，手机号码已存在" );
        } else if ( StringUtils.isNotEmpty ( user.getEmail () )
                && UserConstants.NOT_UNIQUE.equals ( userService.checkEmailUnique ( user ) ) ) {
            return AjaxResult.error ( "新增用户'" + user.getUserName () + "'失败，邮箱账号已存在" );
        }
        user.setCreateBy ( getUsername () );
        user.setPassword ( SecurityUtils.encryptPassword ( user.getPassword () ) );
        return toAjax ( userService.insertUser ( user ) );*/
        if ( UserConstants.NOT_UNIQUE.equals ( userService.checkUserNameUnique ( user.getUserName () ) ) ){
            return AjaxResult.error ("新增用户"+user.getUserName ()+"失败，登录账号已经存在");
        }else if ( StringUtils.isNotEmpty ( user.getPhonenumber () ) && UserConstants.NOT_UNIQUE.equals ( userService.checkPhoneUnique ( user ) )){
            return AjaxResult.error ("新增用户"+user.getUserName ()+"失败，手机号码已经存在");
        }else if ( StringUtils.isNotEmpty ( user.getEmail () ) && UserConstants.NOT_UNIQUE.equals ( userService.checkEmailUnique ( user ) )){
            return AjaxResult.error ("新增用户"+user.getUserName ()+"失败，邮箱账号已经存在");
        }
        user.setCreateBy ( getUsername () );
        user.setPassword ( SecurityUtils.encryptPassword ( user.getPassword () ) );
        return toAjax ( userService.insertUser ( user ) );
    }

    /**
     * 修改用户
     */
    @PreAuthorize("@ss.hasPermi('system:user:edit')")
    @Log(title = "用户管理", businessType = BusinessType.UPDATE)
    @PutMapping
    public AjaxResult edit(@Validated @RequestBody SysUser user) {
        /*userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        if ( StringUtils.isNotEmpty ( user.getPhonenumber () )
                && UserConstants.NOT_UNIQUE.equals ( userService.checkPhoneUnique ( user ) ) ) {
            return AjaxResult.error ( "修改用户'" + user.getUserName () + "'失败，手机号码已存在" );
        } else if ( StringUtils.isNotEmpty ( user.getEmail () )
                && UserConstants.NOT_UNIQUE.equals ( userService.checkEmailUnique ( user ) ) ) {
            return AjaxResult.error ( "修改用户'" + user.getUserName () + "'失败，邮箱账号已存在" );
        }
        user.setUpdateBy ( getUsername () );
        return toAjax ( userService.updateUser ( user ) );*/
        userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        //做一个判断 根据用户
        if ( StringUtils.isNotEmpty ( user.getPhonenumber () ) && UserConstants.NOT_UNIQUE.equals ( userService.checkPhoneUnique ( user ) ) ) {
            return AjaxResult.error ( "修改用户" + user.getUserName () + "失败，手机号已经存在" );
        } else if ( StringUtils.isNotEmpty ( user.getEmail () ) && UserConstants.NOT_UNIQUE.equals ( userService.checkEmailUnique ( user ) ) ) {
            return AjaxResult.error ( "修改用户" + user.getUserName () + "失败，邮箱已经存在" );
        }
        user.setUpdateBy ( getUsername () );
        return toAjax ( userService.updateUser ( user ) );
    }

        /**
     * 删除用户
     */
    @PreAuthorize("@ss.hasPermi('system:user:remove')")
    @Log(title = "用户管理", businessType = BusinessType.DELETE)
    @DeleteMapping("/{userIds}")
    public AjaxResult remove(@PathVariable Long[] userIds) {
        /*if ( ArrayUtils.contains ( userIds, getUserId () ) ) {
            return error ( "当前用户不能删除" );
        }
        return toAjax ( userService.deleteUserByIds ( userIds ) );*/
        if ( ArrayUtils.contains ( userIds ,getUserId ()) ){
            return error ("当前的用户不能被删除");
        }
        return toAjax ( userService.deleteUserByIds ( userIds ) );
    }

    /**
     * 重置密码
     */
    @PreAuthorize("@ss.hasPermi('system:user:resetPwd')")
    @Log(title = "用户管理", businessType = BusinessType.UPDATE)
    @PutMapping("/resetPwd")
    public AjaxResult resetPwd(@RequestBody SysUser user) {
        /*userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        user.setPassword ( SecurityUtils.encryptPassword ( user.getPassword () ) );
        user.setUpdateBy ( getUsername () );
        return toAjax ( userService.resetPwd ( user ) );*/
        //用于获取用户的id
        userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        //重置密码 重新根据用户的名字修改密码 然后发送ajax异步请求，实现局部刷新 这个方法也可以直接写在页面 用写应该定时器定时刷新
        // user.setPassword ( SecurityUtils.encryptPassword ( user.getPassword () ) );
        user.setUpdateBy ( getUsername () );
        return toAjax ( userService.resetPwd ( user ) );
    }

    /**
     * 状态修改
     */
    @PreAuthorize("@ss.hasPermi('system:user:edit')")
    @Log(title = "用户管理", businessType = BusinessType.UPDATE)
    @PutMapping("/changeStatus")
    public AjaxResult changeStatus(@RequestBody SysUser user) {
        /*userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        user.setUpdateBy ( getUsername () );
        return toAjax ( userService.updateUserStatus ( user ) );*/
        userService.checkUserAllowed ( user );
        userService.checkUserDataScope ( user.getUserId () );
        user.setUpdateBy ( getUsername () );
        //根据用户修改相应的状态，同时也刷新一下状态
        return toAjax (userService.updateUserStatus ( user ));
    }

    /**
     * 根据用户编号获取授权角色
     */
    @PreAuthorize("@ss.hasPermi('system:user:query')")
    @GetMapping("/authRole/{userId}")
    public AjaxResult authRole(@PathVariable("userId") Long userId) {
        /*AjaxResult ajax = AjaxResult.success ();
        SysUser user = userService.selectUserById ( userId );
        List<SysRole> roles = roleService.selectRolesByUserId ( userId );
        ajax.put ( "user", user );
        ajax.put ( "roles", SysUser.isAdmin ( userId ) ? roles : roles.stream ().filter ( r -> !r.isAdmin () ).collect ( Collectors.toList () ) );
        return ajax;*/
        AjaxResult ajax=AjaxResult.success ();
        SysUser user=userService.selectUserById ( userId);
        List<SysRole> roles=roleService.selectRolesByUserId ( userId );
        ajax.put ( "user",user );
        ajax.put ( "roles",SysUser.isAdmin ( userId )?roles:roles.stream ().filter ( r->!r.isAdmin () ).collect ( Collectors.toList () ) );
        return ajax;
    }

    /**
     * 用户授权角色
     */
    @PreAuthorize("@ss.hasPermi('system:user:edit')")
    @Log(title = "用户管理", businessType = BusinessType.GRANT)
    @PutMapping("/authRole")
    public AjaxResult insertAuthRole(Long userId, Long[] roleIds) {
        userService.checkUserDataScope ( userId );
        userService.insertUserAuth ( userId, roleIds );
        return success ();
    }



}
