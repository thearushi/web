/**
 * VigilSec Cyber Background Engine
 * High-performance 60FPS multi-layer Canvas animation:
 * - Deep cyberpunk space background (#050510 -> #0A0D1A)
 * - 3D Perspective Digital Grid Floor at bottom
 * - Futuristic Dual Undulating Wireframe Wave Mesh (Electric Blue & Crimson/Purple)
 * - Abstract Cybersecurity Constellation Network (Floating nodes & connecting lines)
 * - Soft ambient cyber glow
 * - NO falling text or Matrix rain showers!
 */

(function () {
    'use strict';

    var doc = (typeof window !== 'undefined' && window.parent && window.parent.document) ? window.parent.document : document;
    var win = (typeof window !== 'undefined' && window.parent) ? window.parent : window;

    if (win.__vigilSecBgRunning) return;
    win.__vigilSecBgRunning = true;

    // Ensure Streamlit App containers stay transparent
    var styleId = 'vigilsec-bg-transparency';
    if (!doc.getElementById(styleId)) {
        var styleEl = doc.createElement('style');
        styleEl.id = styleId;
        styleEl.textContent = `
            .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"], 
            [data-testid="stMainBlockContainer"], .main, header[data-testid="stHeader"],
            section.main, div[data-testid="stVerticalBlock"] {
                background: transparent !important;
                background-color: transparent !important;
            }
        `;
        doc.head.appendChild(styleEl);
    }

    var canvas = doc.getElementById('cyber-bg-canvas');
    if (!canvas) {
        canvas = doc.createElement('canvas');
        canvas.id = 'cyber-bg-canvas';
        canvas.style.cssText = 'position:fixed!important;top:0!important;left:0!important;width:100vw!important;height:100vh!important;z-index:0!important;pointer-events:none!important;background:#050510;';
        doc.body.insertBefore(canvas, doc.body.firstChild);
    }

    var ctx = canvas.getContext('2d');
    if (!ctx) return;

    var width = (canvas.width = win.innerWidth);
    var height = (canvas.height = win.innerHeight);

    var mouse = { x: width * 0.5, y: height * 0.3, active: false };

    win.addEventListener('resize', function () {
        width = canvas.width = win.innerWidth;
        height = canvas.height = win.innerHeight;
        initConstellation();
    });

    win.addEventListener('mousemove', function (e) {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
        mouse.active = true;
    });

    win.addEventListener('mouseleave', function () {
        mouse.active = false;
    });

    // -------------------------------------------------------------
    // Constellation Network Nodes
    // -------------------------------------------------------------
    var nodes = [];
    var numNodes = 28;

    function initConstellation() {
        nodes = [];
        var palette = ['#087BFF', '#9B30FF', '#00E5FF', '#FF1744'];
        for (var i = 0; i < numNodes; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * (height * 0.75),
                vx: (Math.random() - 0.5) * 0.45,
                vy: (Math.random() - 0.5) * 0.45,
                radius: Math.random() * 2 + 1.2,
                color: palette[Math.floor(Math.random() * palette.length)],
                pulse: Math.random() * Math.PI * 2
            });
        }
    }
    initConstellation();

    // -------------------------------------------------------------
    // Render Loop
    // -------------------------------------------------------------
    var time = 0;
    var gridOffset = 0;

    function render() {
        time += 0.015;
        gridOffset = (gridOffset + 0.45) % 36;

        // Base gradient background
        var bgGrad = ctx.createLinearGradient(0, 0, 0, height);
        bgGrad.addColorStop(0, '#050510');
        bgGrad.addColorStop(0.55, '#070A18');
        bgGrad.addColorStop(1, '#0A0D1A');
        ctx.fillStyle = bgGrad;
        ctx.fillRect(0, 0, width, height);

        // Ambient radial glows (Blue on left, Purple center, Crimson on right)
        var glowLeft = ctx.createRadialGradient(width * 0.22, height * 0.25, 10, width * 0.22, height * 0.25, width * 0.45);
        glowLeft.addColorStop(0, 'rgba(8, 123, 255, 0.08)');
        glowLeft.addColorStop(1, 'rgba(8, 123, 255, 0)');
        ctx.fillStyle = glowLeft;
        ctx.fillRect(0, 0, width, height);

        var glowRight = ctx.createRadialGradient(width * 0.78, height * 0.22, 10, width * 0.78, height * 0.22, width * 0.45);
        glowRight.addColorStop(0, 'rgba(255, 23, 68, 0.07)');
        glowRight.addColorStop(1, 'rgba(255, 23, 68, 0)');
        ctx.fillStyle = glowRight;
        ctx.fillRect(0, 0, width, height);

        var glowCenter = ctx.createRadialGradient(width * 0.5, height * 0.4, 20, width * 0.5, height * 0.4, width * 0.35);
        glowCenter.addColorStop(0, 'rgba(155, 48, 255, 0.06)');
        glowCenter.addColorStop(1, 'rgba(155, 48, 255, 0)');
        ctx.fillStyle = glowCenter;
        ctx.fillRect(0, 0, width, height);

        // ---------------------------------------------------------
        // 1. Digital Perspective Grid Floor (Bottom Horizon)
        // ---------------------------------------------------------
        ctx.save();
        var horizonY = height * 0.72;
        var centerX = width * 0.5;

        // Perspective longitudinal lines
        ctx.strokeStyle = 'rgba(8, 123, 255, 0.09)';
        ctx.lineWidth = 1;
        var numRays = 34;
        for (var r = -numRays; r <= numRays; r++) {
            var bottomX = centerX + r * (width / 22);
            ctx.beginPath();
            ctx.moveTo(centerX + (r * (width / 60)), horizonY);
            ctx.lineTo(bottomX, height);
            ctx.stroke();
        }

        // Horizontal perspective lines moving forward
        for (var d = 1; d <= 12; d++) {
            var progress = ((d * 30 + gridOffset) % 360) / 360;
            var curY = horizonY + Math.pow(progress, 2.2) * (height - horizonY);
            var alpha = Math.min(1, progress * 1.5) * 0.14;
            ctx.strokeStyle = 'rgba(0, 229, 255, ' + alpha + ')';
            ctx.beginPath();
            ctx.moveTo(0, curY);
            ctx.lineTo(width, curY);
            ctx.stroke();
        }
        ctx.restore();

        // ---------------------------------------------------------
        // 2. Futuristic Undulating Wireframe Cyber Waves at Bottom
        // ---------------------------------------------------------
        ctx.save();
        var waveBaseY = height - 42;
        var waveSegments = 40;
        var segWidth = width / waveSegments;

        // Left Wave Mesh: Electric Blue & Cyan
        var numRibbons = 6;
        for (var rib = 0; rib < numRibbons; rib++) {
            var ribOffset = rib * 6;
            var alphaRib = (0.28 - rib * 0.035);
            ctx.strokeStyle = 'rgba(8, 123, 255, ' + alphaRib + ')';
            ctx.lineWidth = 1.3;
            ctx.beginPath();
            for (var s = 0; s <= waveSegments * 0.65; s++) {
                var px = s * segWidth;
                var py = waveBaseY - ribOffset +
                    Math.sin(time * 1.5 + s * 0.22) * 18 * (1 - s / (waveSegments * 0.65)) +
                    Math.cos(time * 0.8 + s * 0.15) * 10;
                if (s === 0) ctx.moveTo(px, py);
                else ctx.lineTo(px, py);
            }
            ctx.stroke();
        }

        // Right Wave Mesh: Crimson Red & Neon Purple
        for (var ribR = 0; ribR < numRibbons; ribR++) {
            var ribOffsetR = ribR * 6;
            var alphaRibR = (0.30 - ribR * 0.04);
            ctx.strokeStyle = (ribR % 2 === 0) ? 'rgba(255, 23, 68, ' + alphaRibR + ')' : 'rgba(155, 48, 255, ' + alphaRibR + ')';
            ctx.lineWidth = 1.3;
            ctx.beginPath();
            var startIdx = Math.floor(waveSegments * 0.35);
            for (var sR = startIdx; sR <= waveSegments; sR++) {
                var pxR = sR * segWidth;
                var distFromRight = (waveSegments - sR) / (waveSegments - startIdx);
                var pyR = waveBaseY - ribOffsetR +
                    Math.sin(time * 1.6 + sR * 0.20 + Math.PI) * 22 * (1 - distFromRight * 0.2) +
                    Math.cos(time * 0.9 + sR * 0.12) * 12;
                if (sR === startIdx) ctx.moveTo(pxR, pyR);
                else ctx.lineTo(pxR, pyR);
            }
            ctx.stroke();
        }

        // Connecting vertical grid ribs for the 3D cyber wireframe effect
        ctx.strokeStyle = 'rgba(0, 229, 255, 0.10)';
        ctx.lineWidth = 0.9;
        for (var v = 0; v <= waveSegments; v += 2) {
            var vx = v * segWidth;
            var topY = waveBaseY - numRibbons * 6 + Math.sin(time * 1.5 + v * 0.2) * 16;
            var botY = waveBaseY + 10;
            ctx.beginPath();
            ctx.moveTo(vx, topY);
            ctx.lineTo(vx, botY);
            ctx.stroke();
        }
        ctx.restore();

        // ---------------------------------------------------------
        // 3. Abstract Constellation Network (Cyber Security Nodes)
        // ---------------------------------------------------------
        ctx.save();
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            n.x += n.vx;
            n.y += n.vy;
            n.pulse += 0.03;

            if (n.x < 0 || n.x > width) n.vx *= -1;
            if (n.y < 0 || n.y > height * 0.72) n.vy *= -1;

            // Connect nearby nodes
            for (var j = i + 1; j < nodes.length; j++) {
                var n2 = nodes[j];
                var dx = n.x - n2.x;
                var dy = n.y - n2.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 130) {
                    var lineAlpha = (1 - dist / 130) * 0.16;
                    ctx.strokeStyle = 'rgba(8, 123, 255, ' + lineAlpha + ')';
                    ctx.lineWidth = 0.8;
                    ctx.beginPath();
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.stroke();
                }
            }

            // Draw glowing node
            var r = n.radius + Math.sin(n.pulse) * 0.6;
            ctx.shadowBlur = 10;
            ctx.shadowColor = n.color;
            ctx.fillStyle = n.color;
            ctx.beginPath();
            ctx.arc(n.x, n.y, Math.max(0.8, r), 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
        }
        ctx.restore();

        win.requestAnimationFrame(render);
    }

    win.requestAnimationFrame(render);
})();
