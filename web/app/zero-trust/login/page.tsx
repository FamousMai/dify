'use client'

import React from 'react'
import ZeroTrustLoginForm from './components/ZeroTrustLoginForm'

const ZeroTrustLoginPage = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="max-w-md w-full space-y-8 p-8">
        <div className="text-center">
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100">
            <svg className="h-6 w-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            零信任身份验证
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            请使用您的零信任系统凭据登录
          </p>
        </div>
        
        <ZeroTrustLoginForm />
        
        <div className="text-center">
          <p className="text-xs text-gray-500">
            此为零信任系统演示界面
          </p>
        </div>
      </div>
    </div>
  )
}

export default ZeroTrustLoginPage 