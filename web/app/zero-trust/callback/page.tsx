'use client'

import React, { useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Loading from '@/app/components/base/loading'
import Toast from '@/app/components/base/toast'
import { getUserTokenInfo } from '@/service/zero-trust'

interface ZeroTrustUser {
  id: string
  username: string
  email: string
  name: string
  department: string
  role: string
  status: string
  last_login_at?: string
  created_at: string
}

interface UserTokenInfoResponse {
  success: boolean
  user: ZeroTrustUser
}

const ZeroTrustCallback = () => {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [message, setMessage] = useState('正在处理零信任身份验证...')

  // 获取URL参数
  const token = searchParams.get('token')
  const redirectUrl = searchParams.get('redirect_url') || '/apps'

  useEffect(() => {
    const processZeroTrustAuth = async () => {
      if (!token) {
        setStatus('error')
        setMessage('缺少身份验证Token')
        return
      }

      try {
        setMessage('正在验证零信任Token...')

        // 步骤1：调用getUserTokenInfo获取用户信息（模拟时序图中的API调用）
        const userInfoData = await getUserTokenInfo(token)
        
        if (!userInfoData.success) {
          throw new Error('获取用户信息失败')
        }

        const zeroTrustUser = userInfoData.user
        setMessage(`欢迎，${zeroTrustUser.name}！正在创建Dify会话...`)

        // 步骤2：将零信任用户信息转换为Dify用户（模拟集成过程）
        // 在实际应用中，这里应该调用Dify的用户创建/登录API
        // 现在我们模拟这个过程，直接使用零信任用户信息

        // 存储用户信息到localStorage（模拟Dify会话）
        const difyUserSession = {
          id: zeroTrustUser.id,
          name: zeroTrustUser.name,
          email: zeroTrustUser.email,
          auth_type: 'zero_trust',
          zero_trust_user: zeroTrustUser,
          access_token: token, // 在实际应用中这应该是Dify的access_token
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24小时后过期
        }

        // 存储到localStorage（模拟Dify的session管理）
        localStorage.setItem('dify_user_session', JSON.stringify(difyUserSession))
        localStorage.setItem('zero_trust_token', token)
        localStorage.setItem('console_token', token) // 临时使用零信任token作为console token

        setStatus('success')
        setMessage(`身份验证成功！正在跳转到Dify工作区...`)

        // 延迟跳转，让用户看到成功消息
        setTimeout(() => {
          Toast.notify({
            type: 'success',
            message: `欢迎使用Dify，${zeroTrustUser.name}！`,
          })
          router.push(redirectUrl)
        }, 2000)

      } catch (error) {
        console.error('Zero trust auth error:', error)
        setStatus('error')
        setMessage(`身份验证失败: ${error instanceof Error ? error.message : '未知错误'}`)
        
        Toast.notify({
          type: 'error',
          message: '身份验证失败，请重新登录',
        })

        // 3秒后跳转回登录页
        setTimeout(() => {
          router.push('/zero-trust/login')
        }, 3000)
      }
    }

    processZeroTrustAuth()
  }, [token, redirectUrl, router])

  const getStatusIcon = () => {
    switch (status) {
      case 'processing':
        return (
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        )
      case 'success':
        return (
          <div className="rounded-full h-12 w-12 bg-green-100 flex items-center justify-center">
            <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
        )
      case 'error':
        return (
          <div className="rounded-full h-12 w-12 bg-red-100 flex items-center justify-center">
            <svg className="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
        )
    }
  }

  const getStatusColor = () => {
    switch (status) {
      case 'processing':
        return 'text-blue-600'
      case 'success':
        return 'text-green-600'
      case 'error':
        return 'text-red-600'
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="max-w-md w-full space-y-8 p-8">
        <div className="text-center">
          <div className="mx-auto mb-6">
            {getStatusIcon()}
          </div>
          
          <h2 className="text-2xl font-extrabold text-gray-900 mb-4">
            零信任身份验证
          </h2>
          
          <p className={`text-sm ${getStatusColor()} mb-6`}>
            {message}
          </p>

          {status === 'processing' && (
            <div className="space-y-3">
              <div className="flex items-center justify-center space-x-2">
                <Loading type="area" />
                <span className="text-sm text-gray-600">处理中...</span>
              </div>
              
              <div className="text-xs text-gray-500 space-y-1">
                <div>✓ 连接零信任系统</div>
                <div className={status === 'processing' ? 'animate-pulse' : ''}>
                  → 验证身份凭据
                </div>
                <div>→ 创建Dify会话</div>
                <div>→ 跳转到工作区</div>
              </div>
            </div>
          )}

          {status === 'success' && (
            <div className="text-sm text-green-600">
              <div className="mb-2">✓ 身份验证成功</div>
              <div>正在跳转到Dify工作区...</div>
            </div>
          )}

          {status === 'error' && (
            <div className="space-y-4">
              <div className="text-sm text-red-600">
                身份验证失败，将自动跳转回登录页
              </div>
              <button
                onClick={() => router.push('/zero-trust/login')}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                返回登录页
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ZeroTrustCallback 