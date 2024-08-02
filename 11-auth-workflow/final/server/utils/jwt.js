const jwt = require('jsonwebtoken')
const { promisify } = require('util')
const jwtVerify = promisify(jwt.verify)
const jwtSign = promisify(jwt.sign)

const createJWT = async ({ payload }) =>
	await jwtSign(payload, process.env.JWT_SECRET, {
		expiresIn: payload.expiresIn,
	})

const isTokenValid = async token =>
	await jwtVerify(token, process.env.JWT_SECRET)

const attachCookiesToResponse = async ({
	res,
	user,
	refreshToken,
	expiresIn,
}) => {
	const accessTokenJWT = await createJWT({
		payload: { user, expiresIn: 60 * 15 },
	}) //set accessJWT 15 mins valid
	const refreshTokenJWT = await createJWT({
		payload: {
			user,
			refreshToken,
			expiresIn: new Date(expiresIn).getTime() - Date.now() - 5 * 60,
			// refreshJWT will be expired 5min ahead the expiredTime saved in DB
		},
	})

	const oneDay = 1000 * 60 * 60 * 24
	const longerExp = 1000 * 60 * 60 * 24 * 30

	res.cookie('accessToken', accessTokenJWT, {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		signed: true,
		expires: new Date(Date.now() + 1000 * 60 * 15), //15min
	})

	res.cookie('refreshToken', refreshTokenJWT, {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		signed: true,
		expires: new Date(expiresIn - 1000 * 60 * 5), // if use Date.now() as reference, the refreshToken will never be expired, which is a bug, so add an expiredIn attribute in Token Schema, and use that as reference, whenever the refreshToken refresh, it's live can also be refreshed correct
	})
}
// const attachSingleCookieToResponse = ({ res, user }) => {
//   const token = createJWT({ payload: user });

//   const oneDay = 1000 * 60 * 60 * 24;

//   res.cookie('token', token, {
//     httpOnly: true,
//     expires: new Date(Date.now() + oneDay),
//     secure: process.env.NODE_ENV === 'production',
//     signed: true,
//   });
// };

module.exports = {
	createJWT,
	isTokenValid,
	attachCookiesToResponse,
}
