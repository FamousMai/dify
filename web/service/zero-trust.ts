import { get, post, getPublic, postPublic } from './base'

// 零信任用户信息接口
export interface ZeroTrustUser {
  id: string
  username: string
  email: string
  name: string
  department: string
  role: string
  status: string
  last_login_at?: string
  failed_login_attempts: number
  created_at: string
  updated_at: string
}

// 登录请求接口
export interface ZeroTrustLoginRequest {
  username: string
  password: string
}

// 登录响应接口
export interface ZeroTrustLoginResponse {
  success: boolean
  token: string
  redirect_url: string
  user: ZeroTrustUser
  message?: string
}

// 获取用户Token信息响应接口
export interface GetUserTokenInfoResponse {
  success: boolean
  user: ZeroTrustUser
}

// Token验证请求接口
export interface ZeroTrustVerifyRequest {
  token: string
}

// Token验证响应接口
export interface ZeroTrustVerifyResponse {
  valid: boolean
  user_id?: string
  message?: string
}

// 用户列表响应接口
export interface ZeroTrustUserListResponse {
  success: boolean
  users: ZeroTrustUser[]
  pagination: {
    page: number
    per_page: number
    total: number
    pages: number
  }
}

// 演示数据初始化响应接口
export interface ZeroTrustDemoInitResponse {
  success: boolean
  message: string
  users: Array<{
    username: string
    email: string
    name: string
    role: string
  }>
}

// 零信任认证API
export const zeroTrustLogin = (data: ZeroTrustLoginRequest) => {
  return postPublic<ZeroTrustLoginResponse>('/zero-trust/auth/login', { body: data })
}

export const getUserTokenInfo = async (token: string): Promise<GetUserTokenInfoResponse> => {
  const response = await fetch('http://localhost:5001/api/zero-trust/auth/getUserTokenInfo', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  })

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`)
  }

  return response.json()
}

export const verifyZeroTrustToken = (data: ZeroTrustVerifyRequest) => {
  return postPublic<ZeroTrustVerifyResponse>('/zero-trust/auth/verify', { body: data })
}

export const logoutZeroTrust = (token: string) => {
  return postPublic('/zero-trust/auth/logout', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  })
}

// 零信任用户管理API
export const getZeroTrustUserProfile = (token: string) => {
  return getPublic<{ success: boolean; user: ZeroTrustUser }>('/zero-trust/user/profile', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  })
}

export const getZeroTrustUserList = (token: string, page = 1, per_page = 20) => {
  return getPublic<ZeroTrustUserListResponse>('/zero-trust/user/list', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
    params: {
      page,
      per_page,
    },
  })
}

// 零信任系统初始化API
export const initZeroTrustDemo = () => {
  return postPublic<ZeroTrustDemoInitResponse>('/zero-trust/init/demo')
} 