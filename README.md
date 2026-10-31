<div align="center">
  <h1>patch_pclce.py</h1>
  <p><strong>移除 PCL-CE 的下载地区限制</strong></p>
</div>

> [!IMPORTANT]
> 需要 Python3.6+

```
把 PCL.Core.App.Region.RegionAssessment.get_IsRestricted 的方法体改成 ldc.i4.0; ret
不改变大小 且 不破坏 bundle 尾部索引

bundle 索引
-> PCL.Core.dll 偏移
-> DLL 的 PE 节表 RVA
-> 文件偏移
-> CLR 元数据 TypeDef
-> MethodDef 行的 RVA
-> 方法体头(12 字节 fat header)
-> IL 起始偏移
```

## 免责声明

1. 本项目仅供个人学习和交流使用。使用者应自行确保其使用行为符合适用的法律法规，符合相关应用的许可协议和服务条款；使用者应自行评估使用本项目的风险，并对其使用行为及由此产生的一切后果负责。在适用法律允许的最大范围内，项目作者及贡献者不对因使用、修改或分发本项目而引起的任何直接或间接损失、纠纷或其他后果承担责任。
2. 本项目按“现状”提供，不作任何明示或默示担保，具体担保排除与责任限制以 LICENSE 为准。
3. 本项目与 PCL-CE 及其开发者、维护者或所属组织无关联。文中提及的应用名称仅用于说明本项目的用途，相关名称及商标归各自权利人所有。

## 许可证

本项目采用 MIT 许可证
第三方依赖依照其相关许可证
