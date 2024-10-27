// src/templates/populated-worker/src/index.js
import renderHtml from './renderHtml.js';
import jwt from '@tsndr/cloudflare-worker-jwt';

const SECRET_KEY = 'this-is-a-secret-key';
const EXPIRE_SEC = 3600 * 24 * 15;
var src_default = {
    async fetch(request, env) {
        // console.log(request);

        const url = new URL(request.url);
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: corsHeaders,
            });
        }

        let response;
        switch (url.pathname) {
            case '/api/upload_image': {
                if (request.method !== 'POST') {
                    response = new Response('method not allowed', { status: 405 });
                    break;
                }

                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    response = new Response(JSON.stringify({ success: false, error: 'no token provided' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    });
                    break;
                }

                const token = authHeader.split(' ')[1];

                try {
                    const isValid = await jwt.verify(token, SECRET_KEY);
                    if (!isValid) {
                        response = new Response(JSON.stringify({ success: false, error: 'invalid token' }), {
                            status: 401,
                            headers: { 'Content-Type': 'application/json' },
                        });
                        break;
                    }

                    const formData = await request.formData();
                    const file = formData.get('image');
                    // console.log('received image size:', file.size);

                    if (!file || !(file instanceof File)) {
                        response = new Response(JSON.stringify({ success: false, error: 'no image provided' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json' },
                        });
                        break;
                    }

                    const { DATABASE } = env;

                    const contentType = file.type;
                    const data = await file.arrayBuffer();
                    const uploadTime = Math.floor(Date.now() / 1000);

                    const maxIdStmt = DATABASE.prepare('SELECT MAX(id) as maxId FROM images');
                    const { maxId } = await maxIdStmt.first();
                    const newId = (maxId || 0) + 1;

                    const stmt = DATABASE.prepare('INSERT INTO images (id, type, upload_time, image_data) VALUES (?, ?, ?, ?)');
                    const result = await stmt.bind(newId, contentType, uploadTime, data).run();

                    if (result.success) {
                        const imageUrl = `${url.origin}/api/image?id=${newId}`;
                        response = new Response(
                            JSON.stringify({
                                success: true,
                                message: 'image upload success',
                                id: newId,
                                url: imageUrl,
                            }),
                            {
                                status: 201,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    } else {
                        throw new Error('image insert failed');
                    }
                } catch (error) {
                    console.error('image upload error:', error);
                    response = new Response(
                        JSON.stringify({
                            error: 'server internal error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/image': {
                const id = url.searchParams.get('id');
                if (!id) {
                    response = new Response('missing image id', { status: 400 });
                    break;
                }
                const { DATABASE } = env;
                const stmt = DATABASE.prepare('SELECT * FROM images WHERE id = ?');
                const result = await stmt.bind(id).first();
                let imageData = result.image_data;
                if (result) {
                    imageData = new Uint8Array(imageData); // transform to Uint8Array !important
                    response = new Response(imageData, {
                        headers: {
                            'Content-Type': result.type,
                            'Access-Control-Allow-Origin': '*', // 允许跨域访问
                        },
                    });

                } else {
                    response = new Response('image not found', { status: 404 });
                }
                break;
            }
            case '/api/all_doc': {
                const { DATABASE } = env;
                try {
                    const stmt = DATABASE.prepare('SELECT * FROM articles');
                    const { results } = await stmt.all();

                    response = new Response(JSON.stringify(results), {
                        headers: { 'Content-Type': 'application/json' },
                    });
                } catch (error) {
                    response = new Response(
                        JSON.stringify({
                            error: 'getting all articles error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/save_doc': {
                if (request.method !== 'POST') {
                    response = new Response('Method Not Allowed', { status: 405 });
                    break;
                }

                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    response = new Response(JSON.stringify({ success: false, error: 'No token provided' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    });
                    break;
                }

                const token = authHeader.split(' ')[1];



                try {
                    const isValid = await jwt.verify(token, SECRET_KEY);
                    if (!isValid) {
                        response = new Response(JSON.stringify({ success: false, error: 'Invalid token' }), {
                            status: 401,
                            headers: { 'Content-Type': 'application/json' },
                        });
                        break;
                    }

                    const { id, title, content } = await request.json();
                    if (!id || !title || !content) {
                        response = new Response('Missing id or title or content', { status: 400 });
                        break;
                    }

                    const { DATABASE } = env;
                    const currentTimestamp = Math.floor(Date.now() / 1000);
                    const stmt = DATABASE.prepare('UPDATE articles SET title = ?, content = ?, update_time = ? WHERE id = ?');

                    const result = await stmt.bind(title, JSON.stringify(content), currentTimestamp, id).run();

                    if (result.success) {
                        response = new Response(
                            JSON.stringify({
                                message: 'update document success',
                                id: id,
                                update_time: currentTimestamp,
                            }),
                            {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    } else {
                        throw new Error('failed update document');
                    }
                } catch (error) {
                    console.error('error updating document:', error);
                    response = new Response(
                        JSON.stringify({
                            error: 'Internal Server Error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/new_doc': {
                if (request.method !== 'POST') {
                    response = new Response('Method Not Allowed', { status: 405 });
                    break;
                }

                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    response = new Response(JSON.stringify({ success: false, error: 'No token provided' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    });
                    break;
                }

                const token = authHeader.split(' ')[1];

                try {
                    const isValid = await jwt.verify(token, SECRET_KEY);
                    if (!isValid) {
                        response = new Response(JSON.stringify({ success: false, error: 'Invalid token' }), {
                            status: 401,
                            headers: { 'Content-Type': 'application/json' },
                        });
                        break;
                    }

                    const { title, content } = await request.json();
                    if (!title || !content) {
                        response = new Response('Missing title or content', { status: 400 });
                        break;
                    }

                    const { DATABASE } = env;
                    const stmt = DATABASE.prepare('INSERT INTO articles (id, title, content, create_time, update_time) VALUES (?, ?, ?, ?, ?)');

                    const maxIdStmt = DATABASE.prepare('SELECT MAX(id) as maxId FROM articles');
                    const { maxId } = await maxIdStmt.first();
                    const newId = (maxId || 0) + 1;
                    const currentTimestamp = Math.floor(Date.now() / 1000);
                    const result = await stmt.bind(newId, title, JSON.stringify(content), currentTimestamp, currentTimestamp).run();

                    // 检查插入是否成功
                    if (result.success) {
                        response = new Response(
                            JSON.stringify({
                                message: 'Document saved successfully',
                                id: newId,
                                create_time: currentTimestamp,
                                update_time: currentTimestamp,
                            }),
                            {
                                status: 201,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    } else {
                        response = new Response(
                            JSON.stringify({
                                error: 'Failed to insert document',
                                message: result,
                            }),
                            {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    }
                } catch (error) {
                    console.error('Error saving document:', error);
                    response = new Response(
                        JSON.stringify({
                            error: 'Internal Server Error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/delete_doc': {
                if (request.method !== 'POST') {
                    response = new Response('Method Not Allowed', { status: 405 });
                    break;
                }

                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    response = new Response(JSON.stringify({ success: false, error: 'No token provided' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    });
                    break;
                }

                const token = authHeader.split(' ')[1];

                try {
                    const isValid = await jwt.verify(token, SECRET_KEY);
                    if (!isValid) {
                        response = new Response(JSON.stringify({ success: false, error: 'Invalid token' }), {
                            status: 401,
                            headers: { 'Content-Type': 'application/json' },
                        });
                        break;
                    }

                    const { id } = await request.json();
                    if (!id) {
                        response = new Response('Missing doc id', { status: 400 });
                        break;
                    }

                    const { DATABASE } = env;
                    const stmt = DATABASE.prepare('DELETE FROM articles WHERE id = ?');

                    const result = await stmt.bind(id).run();

                    if (result.success) {
                        response = new Response(
                            JSON.stringify({
                                success: true,
                                message: 'delete document success',
                                id: id,
                            }),
                            {
                                status: 200,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    } else {
                        throw new Error('delete document failed');
                    }
                } catch (error) {
                    console.error('error delete document:', error);
                    response = new Response(
                        JSON.stringify({
                            error: 'Internal Server Error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/login': {
                if (request.method !== 'POST') {
                    response = new Response('Method Not Allowed', { status: 405 });
                    break;
                }

                const { DATABASE } = env;
                try {
                    const { pwd_hash } = await request.json();
                    if (!pwd_hash) {
                        response = new Response(
                            JSON.stringify({
                                error: 'Missing password hash',
                            }),
                            {
                                status: 400,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                        break;
                    }

                    const stmt = DATABASE.prepare('SELECT pwd FROM pwd WHERE id=0');
                    const result = await stmt.first();

                    if (!result) {
                        response = new Response(
                            JSON.stringify({
                                error: 'Password not found in database',
                            }),
                            {
                                status: 500,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                        break;
                    }

                    const storedHash = result.pwd;

                    if (pwd_hash === storedHash) {
                        try {
                            // 生成 JWT token
                            const token = await jwt.sign(
                                {
                                    admin: true,
                                    // 可以添加其他你需要的信息，比如：
                                    // userId: "admin",
                                    // role: "administrator",
                                    nbf: Math.floor(Date.now() / 1000), // Not before: 现在
                                    exp: Math.floor(Date.now() / 1000) + EXPIRE_SEC, // expire time 1min
                                },
                                SECRET_KEY
                            );

                            response = new Response(
                                JSON.stringify({
                                    success: true,
                                    message: 'Login successful',
                                    token: token,
                                }),
                                {
                                    status: 200,
                                    headers: { 'Content-Type': 'application/json' },
                                }
                            );
                        } catch (error) {
                            console.error('Error generating token:', error);
                            response = new Response(
                                JSON.stringify({
                                    error: 'Internal Server Error',
                                    message: 'Failed to generate authentication token',
                                }),
                                {
                                    status: 500,
                                    headers: { 'Content-Type': 'application/json' },
                                }
                            );
                        }
                    } else {
                        response = new Response(
                            JSON.stringify({
                                success: false,
                                error: 'Invalid password',
                                result: result,
                            }),
                            {
                                status: 401,
                                headers: { 'Content-Type': 'application/json' },
                            }
                        );
                    }
                } catch (error) {
                    console.error('Error during login:', error);
                    response = new Response(
                        JSON.stringify({
                            error: 'Internal Server Error',
                            message: error.message,
                        }),
                        {
                            status: 500,
                            headers: { 'Content-Type': 'application/json' },
                        }
                    );
                }
                break;
            }
            case '/api/verify_token': {
                if (request.method !== 'POST') {
                    response = new Response('Method Not Allowed', { status: 405 });
                    break;
                }

                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    response = new Response(JSON.stringify({ success: false, error: 'No token provided' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    });
                    break;
                }

                const token = authHeader.split(' ')[1];

                try {
                    const isValid = await jwt.verify(token, SECRET_KEY);
                    if (isValid) {
                        response = new Response(JSON.stringify({ success: true, message: 'Token is valid' }), {
                            status: 200,
                            headers: { 'Content-Type': 'application/json' },
                        });
                    } else {
                        response = new Response(JSON.stringify({ success: false, error: 'Invalid token' }), {
                            status: 401,
                            headers: { 'Content-Type': 'application/json' },
                        });
                    }
                } catch (error) {
                    console.error('Error verifying token:', error);
                    response = new Response(JSON.stringify({ success: false, error: 'Error verifying token' }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json' },
                    });
                }

                break;
            }
            case '/api/all-d1': {
                const { DATABASE } = env;
                const stmt = DATABASE.prepare('SELECT * FROM comments');
                const { results } = await stmt.all();

                response = new Response(JSON.stringify(results, null, 2), {
                    headers: { 'Content-Type': 'application/json' },
                });
                break;
            }
            case '/': {
                // response = Response.redirect("http://klz-personalsite-cf-vite-react-ts.pages.dev", 301);
                const { DATABASE } = env;
                const stmt = DATABASE.prepare('SELECT * FROM comments');
                const { results } = await stmt.all();

                response = new Response(renderHtml(JSON.stringify(results, null, 2)), {
                    headers: {
                        'content-type': 'text/html',
                    },
                });
                break;
            }
            default:
                response = new Response('Not Found', { status: 404, headers: corsHeaders });
        }

        // 为所有响应添加CORS头部
        Object.entries(corsHeaders).forEach(([key, value]) => {
            response.headers.set(key, value);
        });
        if (url.pathname !== '/') {
        }

        return response;
    },
};
export { src_default as default };
