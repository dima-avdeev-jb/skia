#version 400
out vec4 sk_FragColor;
uniform vec4 src;
uniform vec4 dst;
vec3 _blend_set_color_saturation_helper(vec3 minMidMax, float sat) {
    if (minMidMax.x < minMidMax.z) {
        return vec3(0.0, (sat * (minMidMax.y - minMidMax.x)) / (minMidMax.z - minMidMax.x), sat);
    } else {
        return vec3(0.0);
    }
}
void main() {
    float _0_alpha = dst.w * src.w;
    vec3 _1_sda = src.xyz * dst.w;
    vec3 _2_dsa = dst.xyz * src.w;
    vec3 _3_blend_set_color_saturation;
    float _4_sat = max(max(_1_sda.x, _1_sda.y), _1_sda.z) - min(min(_1_sda.x, _1_sda.y), _1_sda.z);
    if (_2_dsa.x <= _2_dsa.y) {
        if (_2_dsa.y <= _2_dsa.z) {
            _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa, _4_sat);
        } else if (_2_dsa.x <= _2_dsa.z) {
            _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa.xzy, _4_sat).xzy;
        } else {
            _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa.zxy, _4_sat).yzx;
        }
    } else if (_2_dsa.x <= _2_dsa.z) {
        _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa.yxz, _4_sat).yxz;
    } else if (_2_dsa.y <= _2_dsa.z) {
        _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa.yzx, _4_sat).zxy;
    } else {
        _3_blend_set_color_saturation = _blend_set_color_saturation_helper(_2_dsa.zyx, _4_sat).zyx;
    }
    vec3 _5_blend_set_color_luminance;
    float _6_lum = dot(vec3(0.30000001192092896, 0.5899999737739563, 0.10999999940395355), _2_dsa);
    vec3 _7_result = (_6_lum - dot(vec3(0.30000001192092896, 0.5899999737739563, 0.10999999940395355), _3_blend_set_color_saturation)) + _3_blend_set_color_saturation;
    float _8_minComp = min(min(_7_result.x, _7_result.y), _7_result.z);
    float _9_maxComp = max(max(_7_result.x, _7_result.y), _7_result.z);
    if (_8_minComp < 0.0 && _6_lum != _8_minComp) {
        _7_result = _6_lum + (_7_result - _6_lum) * (_6_lum / (_6_lum - _8_minComp));
    }
    if (_9_maxComp > _0_alpha && _9_maxComp != _6_lum) {
        _5_blend_set_color_luminance = _6_lum + ((_7_result - _6_lum) * (_0_alpha - _6_lum)) / (_9_maxComp - _6_lum);
    } else {
        _5_blend_set_color_luminance = _7_result;
    }
    sk_FragColor = vec4((((_5_blend_set_color_luminance + dst.xyz) - _2_dsa) + src.xyz) - _1_sda, (src.w + dst.w) - _0_alpha);
}
