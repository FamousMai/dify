'use client'

import React, { useState } from 'react'
import { useRouter } from 'next/navigation'
import Toast from '@/app/components/base/toast'
import Loading from '@/app/components/base/loading'
import { initZeroTrustDemo } from '@/service/zero-trust'

interface DemoUser {
  username: string
  email: string
  name: string
  role: string
}

interface DemoInitResponse {
  success: boolean
  message: string
  users: DemoUser[]
}

const ZeroTrustAdmin = () => {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [demoUsers, setDemoUsers] = useState<DemoUser[]>([])
  const [initialized, setInitialized] = useState(false)

  const handleInitDemo = async () => {
    setLoading(true)
    try {
      const response = await initZeroTrustDemo()
      
      if (response.success) {
        setDemoUsers(response.users)
        setInitialized(true)
        
        Toast.notify({
          type: 'success',
          message: response.message,
        })
      } else {
        Toast.notify({
          type: 'error',
          message: '初始化失败',
        })
      }
    } catch (error) {
      console.error('初始化演示数据失败:', error)
      Toast.notify({
        type: 'error',
        message: '初始化失败，请重试',
      })
    } finally {
      setLoading(false)
    }
  }

  const goToLogin = () => {
    router.push('/zero-trust/login')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          {/* 头部 */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              零信任系统管理
            </h1>
            <p className="text-gray-600">
              初始化演示数据并测试零信任登录功能
            </p>
          </div>

          {/* 导航卡片 */}
          <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-gray-900 mb-2">
                  快速开始
                </h2>
                <p className="text-gray-600">
                  使用预配置的演示账户快速体验零信任登录
                </p>
              </div>
              <button
                onClick={goToLogin}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                前往登录
              </button>
            </div>
          </div>

          {/* 演示数据初始化 */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">
              演示数据初始化
            </h2>
            
            <div className="mb-6">
              <p className="text-gray-600 mb-4">
                点击下方按钮初始化演示用户数据。这将创建预配置的用户账户用于测试零信任登录功能。
              </p>
              
              <button
                onClick={handleInitDemo}
                disabled={loading}
                className={`px-6 py-3 rounded-lg font-medium transition-colors ${
                  loading
                    ? 'bg-gray-400 cursor-not-allowed text-white'
                    : 'bg-green-600 hover:bg-green-700 text-white'
                }`}
              >
                {loading ? (
                  <div className="flex items-center space-x-2">
                    <Loading type="area" />
                    <span>初始化中...</span>
                  </div>
                ) : (
                  '初始化演示数据'
                )}
              </button>
            </div>

            {/* 演示用户列表 */}
            {initialized && demoUsers.length > 0 && (
              <div className="border-t pt-6">
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  已创建的演示用户
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {demoUsers.map((user) => (
                    <div key={user.username} className="border rounded-lg p-4 bg-gray-50">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{user.name}</h4>
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          user.role === 'admin' 
                            ? 'bg-red-100 text-red-800' 
                            : user.role === 'manager'
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-green-100 text-green-800'
                        }`}>
                          {user.role}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-1">
                        <span className="font-medium">用户名:</span> {user.username}
                      </p>
                      <p className="text-sm text-gray-600 mb-3">
                        <span className="font-medium">邮箱:</span> {user.email}
                      </p>
                      <div className="text-xs text-gray-500 bg-white p-2 rounded border">
                        <span className="font-medium">密码:</span> {
                          user.role === 'admin' ? 'Admin123!' :
                          user.role === 'manager' ? 'Manager123!' : 'User123!'
                        }
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium text-blue-900 mb-1">
                        使用说明
                      </h4>
                      <ul className="text-sm text-blue-800 space-y-1">
                        <li>• 使用以上任意账户登录零信任系统</li>
                        <li>• 登录成功后将自动跳转到Dify工作区</li>
                        <li>• 管理员账户具有完整的系统访问权限</li>
                        <li>• 演示数据可以重复初始化（会覆盖现有数据）</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* 系统架构说明 */}
          <div className="bg-white rounded-lg shadow-lg p-6 mt-8">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">
              零信任系统架构
            </h2>
            <div className="space-y-3 text-gray-600">
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm font-medium">1</span>
                </div>
                <p>用户在零信任UI服务中进行身份验证</p>
              </div>
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm font-medium">2</span>
                </div>
                <p>零信任系统验证成功后跳转到Dify前端</p>
              </div>
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm font-medium">3</span>
                </div>
                <p>Dify前端调用零信任API获取用户Token信息</p>
              </div>
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm font-medium">4</span>
                </div>
                <p>系统自动创建或关联Dify账户并生成登录令牌</p>
              </div>
              <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                  <span className="text-blue-600 text-sm font-medium">5</span>
                </div>
                <p>用户成功登录Dify工作区</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ZeroTrustAdmin 