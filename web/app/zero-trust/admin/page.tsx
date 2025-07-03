'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import Loading from '@/app/components/base/loading'
import Toast from '@/app/components/base/toast'
import { getZeroTrustUserList, initZeroTrustDemo } from '@/service/zero-trust'
import type { ZeroTrustUser, ZeroTrustUserListResponse, ZeroTrustDemoInitResponse } from '@/service/zero-trust'



const ZeroTrustAdminPage = () => {
  const router = useRouter()
  const [users, setUsers] = useState<ZeroTrustUser[]>([])
  const [loading, setLoading] = useState(true)
  const [isInitializing, setIsInitializing] = useState(false)
  const [currentUser, setCurrentUser] = useState<any>(null)

  // 检查管理员权限
  useEffect(() => {
    const checkAuth = () => {
      const userSession = localStorage.getItem('dify_user_session')
      if (!userSession) {
        Toast.notify({
          type: 'error',
          message: '请先登录',
        })
        router.push('/zero-trust/login?redirect_url=/zero-trust/admin')
        return
      }

      try {
        const user = JSON.parse(userSession)
        setCurrentUser(user)
        
        if (user.zero_trust_user?.role !== 'admin') {
          Toast.notify({
            type: 'error',
            message: '权限不足，只有管理员可以访问此页面',
          })
          router.push('/apps')
          return
        }
      } catch (error) {
        console.error('解析用户信息失败:', error)
        router.push('/zero-trust/login')
        return
      }
    }

    checkAuth()
  }, [router])

  // 加载用户列表
  const loadUsers = async () => {
    if (!currentUser) return
    
    try {
      const token = localStorage.getItem('zero_trust_token')
      if (!token) {
        throw new Error('未找到认证Token')
      }

      const data = await getZeroTrustUserList(token)
      if (data.success) {
        setUsers(data.users)
      } else {
        throw new Error('获取用户列表失败')
      }
    } catch (error) {
      console.error('加载用户列表错误:', error)
      Toast.notify({
        type: 'error',
        message: error instanceof Error ? error.message : '加载用户列表失败',
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (currentUser) {
      loadUsers()
    }
  }, [currentUser])

  // 初始化演示数据
  const handleInitDemo = async () => {
    setIsInitializing(true)
    
    try {
      const data = await initZeroTrustDemo()
      
      if (data.success) {
        Toast.notify({
          type: 'success',
          message: data.message,
        })
        
        // 重新加载用户列表
        await loadUsers()
      } else {
        throw new Error(data.message || '初始化演示数据失败')
      }
    } catch (error) {
      console.error('初始化演示数据错误:', error)
      Toast.notify({
        type: 'error',
        message: error instanceof Error ? error.message : '初始化演示数据失败',
      })
    } finally {
      setIsInitializing(false)
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN')
  }

  const getStatusBadge = (status: string) => {
    const statusMap = {
      'active': { text: '活跃', color: 'bg-green-100 text-green-800' },
      'inactive': { text: '未激活', color: 'bg-gray-100 text-gray-800' },
      'locked': { text: '锁定', color: 'bg-red-100 text-red-800' },
      'suspended': { text: '暂停', color: 'bg-yellow-100 text-yellow-800' },
    }
    
    const statusInfo = statusMap[status as keyof typeof statusMap] || { text: status, color: 'bg-gray-100 text-gray-800' }
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusInfo.color}`}>
        {statusInfo.text}
      </span>
    )
  }

  const getRoleBadge = (role: string) => {
    const roleMap = {
      'admin': { text: '管理员', color: 'bg-purple-100 text-purple-800' },
      'manager': { text: '经理', color: 'bg-blue-100 text-blue-800' },
      'user': { text: '用户', color: 'bg-gray-100 text-gray-800' },
      'guest': { text: '访客', color: 'bg-yellow-100 text-yellow-800' },
    }
    
    const roleInfo = roleMap[role as keyof typeof roleMap] || { text: role, color: 'bg-gray-100 text-gray-800' }
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${roleInfo.color}`}>
        {roleInfo.text}
      </span>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loading type="area" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* 页面头部 */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">零信任系统管理</h1>
              <p className="mt-2 text-gray-600">
                管理零信任用户和系统配置
                {currentUser && (
                  <span className="ml-2 text-sm">
                    当前用户: {currentUser.name} ({currentUser.zero_trust_user?.role})
                  </span>
                )}
              </p>
            </div>
            <div className="flex space-x-4">
              <button
                onClick={handleInitDemo}
                disabled={isInitializing}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {isInitializing ? (
                  <>
                    <Loading type="area" />
                    <span className="ml-2">初始化中...</span>
                  </>
                ) : (
                  '初始化演示数据'
                )}
              </button>
              <button
                onClick={() => router.push('/apps')}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                返回Dify
              </button>
            </div>
          </div>
        </div>

        {/* 统计卡片 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-blue-500 rounded-md flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">总用户数</dt>
                  <dd className="text-lg font-medium text-gray-900">{users.length}</dd>
                </dl>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">活跃用户</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {users.filter(user => user.status === 'active').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-purple-500 rounded-md flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z" />
                  </svg>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">管理员</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {users.filter(user => user.role === 'admin').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="w-8 h-8 bg-red-500 rounded-md flex items-center justify-center">
                  <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                  </svg>
                </div>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">锁定用户</dt>
                  <dd className="text-lg font-medium text-gray-900">
                    {users.filter(user => user.status === 'locked').length}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        {/* 用户列表 */}
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">用户列表</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    用户信息
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    部门
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    角色
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    状态
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    最后登录
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    失败次数
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10">
                          <div className="h-10 w-10 rounded-full bg-gray-300 flex items-center justify-center">
                            <span className="text-sm font-medium text-gray-700">
                              {user.name.charAt(0)}
                            </span>
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">{user.name}</div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                          <div className="text-xs text-gray-400">@{user.username}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {user.department || '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getRoleBadge(user.role)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(user.status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {user.last_login_at ? formatDate(user.last_login_at) : '从未登录'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {user.failed_login_attempts}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          {users.length === 0 && (
            <div className="text-center py-12">
              <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2 2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">暂无用户数据</h3>
              <p className="mt-1 text-sm text-gray-500">点击"初始化演示数据"按钮创建演示用户</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ZeroTrustAdminPage 