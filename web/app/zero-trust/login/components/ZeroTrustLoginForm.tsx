'use client'

import React, { useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Loading from '@/app/components/base/loading'
import Toast from '@/app/components/base/toast'
import { zeroTrustLogin } from '@/service/zero-trust'
import type { ZeroTrustLoginRequest } from '@/service/zero-trust'

interface LoginFormData {
  username: string
  password: string
}

interface LoginResponse {
  success: boolean
  token: string
  redirect_url: string
  message?: string
  user: {
    id: string
    username: string
    email: string
    name: string
    department: string
    role: string
  }
}

const ZeroTrustLoginForm = () => {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [formData, setFormData] = useState<LoginFormData>({
    username: 'admin',
    password: 'Admin123!',
  })
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  // 获取重定向URL参数
  const redirectUrl = searchParams.get('redirect_url') || '/apps'

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value,
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.username.trim() || !formData.password) {
      Toast.notify({
        type: 'error',
        message: '请填写用户名和密码',
      })
      return
    }

    setIsLoading(true)

    try {
      // 调用零信任登录API
      const loginRequest: ZeroTrustLoginRequest = {
        username: formData.username.trim(),
        password: formData.password,
      }

      const data = await zeroTrustLogin(loginRequest)

      if (data.success) {
        // 登录成功
        Toast.notify({
          type: 'success',
          message: `欢迎，${data.user.name}！`,
        })

        // 存储零信任Token（用于后续API调用）
        localStorage.setItem('zero_trust_token', data.token)
        localStorage.setItem('zero_trust_user', JSON.stringify(data.user))

        // 模拟时序图中的流程：
        // 1. 零信任登录成功，获取到Token
        // 2. 现在需要携带Token跳转到Dify前端
        // 3. Dify前端会调用getUserTokenInfo获取用户信息
        // 4. 然后集成到Dify的用户系统中

        // 跳转到Dify系统（携带零信任Token）
        const difyRedirectUrl = `/zero-trust/callback?token=${encodeURIComponent(data.token)}&redirect_url=${encodeURIComponent(redirectUrl)}`
        router.push(difyRedirectUrl)

      } else {
        // 登录失败
        Toast.notify({
          type: 'error',
          message: data.message || '登录失败，请检查用户名和密码',
        })
      }
    } catch (error) {
      console.error('Login error:', error)
      Toast.notify({
        type: 'error',
        message: '网络错误，请稍后重试',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="bg-white shadow-xl rounded-lg p-8">
      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
            用户名或邮箱
          </label>
          <input
            id="username"
            name="username"
            type="text"
            required
            value={formData.username}
            onChange={handleInputChange}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="请输入用户名或邮箱"
            disabled={isLoading}
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
            密码
          </label>
          <div className="relative">
            <input
              id="password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              required
              value={formData.password}
              onChange={handleInputChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-10"
              placeholder="请输入密码"
              disabled={isLoading}
            />
            <button
              type="button"
              className="absolute inset-y-0 right-0 pr-3 flex items-center"
              onClick={() => setShowPassword(!showPassword)}
              disabled={isLoading}
            >
              <svg
                className="h-5 w-5 text-gray-400 hover:text-gray-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                {showPassword ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                )}
              </svg>
            </button>
          </div>
        </div>

        <div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <div className="flex items-center">
                <Loading type="area" />
                <span className="ml-2">登录中...</span>
              </div>
            ) : (
              '登 录'
            )}
          </button>
        </div>
      </form>

      {/* 演示账户提示 */}
      <div className="mt-6 p-4 bg-blue-50 rounded-md">
        <h4 className="text-sm font-medium text-blue-800 mb-2">演示账户：</h4>
        <div className="text-xs text-blue-700 space-y-1">
          <div>管理员: admin / Admin123!</div>
          <div>用户: john.doe / User123!</div>
          <div>经理: jane.smith / Manager123!</div>
        </div>
        <p className="text-xs text-blue-600 mt-2">
          首次使用请先初始化演示数据
        </p>
      </div>
    </div>
  )
}

export default ZeroTrustLoginForm 