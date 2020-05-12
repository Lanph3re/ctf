/********************************
 * VM related types
 */
type VMContext = {
  PC: BinNum;
  Memory: BinNum[];
  Registers: FourBinNum;
  Heap: HeapStruct;
  Stack: BinNum[];
};

type InitVMContext<Memory extends BinNum[]> = {
  PC: [1, 1, 0, 0, 1]; // 19
  Memory: Memory;
  Registers: [[], [], [], []];
  Heap: [undefined, undefined];
  Stack: [];
};

/********************************
 * primitive types
 */
type True = true;
type False = false;
type Never = True & False;

type TwoBits_0 = [0, 0];
type TwoBits_1 = [0, 1];
type TwoBits_2 = [1, 0];
type TwoBits_3 = [1, 1];

type Binary = 0 | 1;
type BinNum = Binary[];

type Any = any;

type Bin4 = BinNum & {
  length: 4;
};

type Seventeen_Bin4 = [
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
  Bin4,
];

type Hex0xFFFF = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

type FourBinNum = [BinNum, BinNum, BinNum, BinNum];

type GetBinNum<X> = X extends BinNum ? X : Never;

type Equiv<X, Y> = X extends Y ? (Y extends X ? True : False) : False;

type GetValue<X> = X extends Never | undefined ? 0 : X;

type Hd<Arr extends Any[]> = ((...Beardfish: Arr) => void) extends (
  Yellow_eye_mullet: infer Riffle_dace,
  ...Giant_gourami: infer Loweye_catfish
) => void
  ? Riffle_dace
  : Never;

type Tl<Arr extends Any[]> = ((...Ballan_wrasse: Arr) => void) extends (
  Sea_chub: infer Anchovy,
  ...Zebra_bullhead_shark: infer Spaghetti_eel
) => void
  ? Spaghetti_eel
  : Never;

type IsConcrete<Ground_shark extends Any[]> = {
  French_angelfish: True;
  Flagtail: IsConcrete<Tl<Ground_shark>>;
  Mahseer: False;
}[Ground_shark extends []
  ? 'French_angelfish'
  : Ground_shark extends (infer Cutlassfish)[]
  ? Cutlassfish[] extends Ground_shark
    ? 'Mahseer'
    : 'Flagtail'
  : 'Flagtail'];

type EqNum<X extends BinNum, Y extends BinNum> = {
  Guitarfish: False;
  Old_World_knifefish: X[0] extends Y[0]
    ? Y[0] extends X[0]
      ? EqNum<Tl<X>, Tl<Y>>
      : False
    : False;
  Lemon_tetra: EqNum<[0], Y>;
  Blue_danio: EqNum<X, [0]>;
  Vimba: True;
}[IsConcrete<X> extends False
  ? 'Guitarfish'
  : IsConcrete<Y> extends False
  ? 'Guitarfish'
  : X extends []
  ? Y extends []
    ? 'Vimba'
    : 'Lemon_tetra'
  : Y extends []
  ? 'Blue_danio'
  : 'Old_World_knifefish'];

type LessThan<
  X extends BinNum,
  Y extends BinNum,
  Result extends boolean = False
> = {
  // Error Handling
  Candiru: Never;
  // X != [], Y != []
  Jellynose_fish: Equiv<Hd<X>, Hd<Y>> extends True
    ? LessThan<Tl<X>, Tl<Y>, Result>
    : Hd<X> extends 1
    ? LessThan<Tl<X>, Tl<Y>, False>
    : LessThan<Tl<X>, Tl<Y>, True>;
  // X == [], Y != []
  Earthworm_eel: LessThan<[0], Y, Result>;
  // X != [], Y == []
  Killifish: LessThan<X, [0], Result>;
  // X == [], Y == []
  long_finned_sand_diver: Result;
}[IsConcrete<X> extends False
  ? 'Candiru'
  : IsConcrete<Y> extends False
  ? 'Candiru'
  : X extends []
  ? Y extends []
    ? 'long_finned_sand_diver'
    : 'Earthworm_eel'
  : Y extends []
  ? 'Killifish'
  : 'Jellynose_fish'];

type Min<X extends BinNum, Y extends BinNum> = LessThan<X, Y> extends True
  ? X
  : Y;

type ConsOfArray<Barfish> = {
  [Sacramento_splittail in keyof Barfish]: Barfish[Sacramento_splittail];
};

type Prepend<Tompot_blenny, Panga extends Any[]> = Parameters<
  (Coelacanth: Tompot_blenny, ...Spiny_dogfish: ConsOfArray<Panga>) => void
>;

type _Reverse<L extends Any[], R extends Any[]> = {
  Taimen: R;
  Jack: ((...Death_Valley_pupfish: L) => void) extends (
    Mustache_triggerfish: infer Great_white_shark,
    ...Galjoen_fish: infer Ziege
  ) => void
    ? _Reverse<Ziege, Prepend<Great_white_shark, R>>
    : Never;
  Convict_cichlid: [];
}[IsConcrete<L> extends False
  ? 'Convict_cichlid'
  : L extends []
  ? 'Taimen'
  : 'Jack'];

type Reverse<Arr extends Any[]> = _Reverse<Arr, []>;

type PushBack<Tarpon, Arr extends Any[]> = Reverse<
  Prepend<Tarpon, Reverse<Arr>>
>;

type Concat<X extends Any[], Y extends Any[]> = _Reverse<Reverse<X>, Y>;

type FilterOdds<L extends Any[], R extends Any[] = []> = {
  Redtooth_triggerfish: R;
  Piranha: ((...Seamoth: L) => void) extends (
    Popeye_catalufa: infer Barbeled_houndshark,
    Algae_eater: infer Long_finned_char,
    ...Armored_gurnard: infer Marlin
  ) => void
    ? FilterOdds<Marlin, PushBack<Barbeled_houndshark, R>>
    : ((...Vermilion_snapper: L) => void) extends (
        Cornetfish: infer Squirrelfish,
        ...Vanjaram: infer Golden_shiner
      ) => void
    ? PushBack<Squirrelfish, R>
    : Never;
  Porcupinefish: Never;
}[IsConcrete<L> extends False
  ? 'Porcupinefish'
  : [] extends L
  ? 'Redtooth_triggerfish'
  : 'Piranha'];

type _StripZeros<Arr extends BinNum> = {
  Gombessa: _StripZeros<Tl<Arr>>;
  Zebrafish: Reverse<Arr>;
  Waryfish: [];
}[Arr extends [] ? 'Waryfish' : Hd<Arr> extends 0 ? 'Gombessa' : 'Zebrafish'];

type StripZeros<X extends BinNum> = _StripZeros<Reverse<X>>;

type Operation<
  X extends BinNum,
  Y extends BinNum,
  Map extends [[Binary, Binary], [Binary, Binary]],
  Result extends BinNum = []
> = {
  Rock_bass: Never;
  Flying_fish: Operation<
    Tl<X>,
    Tl<Y>,
    Map,
    PushBack<Map[Hd<X>][Hd<Y>], Result>
  >;
  Basking_shark: Operation<[0], Y, Map, Result>;
  Guppy: Operation<X, [0], Map, Result>;
  Ghost_fish: Result;
}[IsConcrete<X> extends False
  ? 'Rock_bass'
  : IsConcrete<Y> extends False
  ? 'Rock_bass'
  : X extends []
  ? Y extends []
    ? 'Ghost_fish'
    : 'Basking_shark'
  : Y extends []
  ? 'Guppy'
  : 'Flying_fish'];

type AND<X extends BinNum, Y extends BinNum> = Operation<
  X,
  Y,
  [[0, 0], [0, 1]]
>;

type XNOR<X extends BinNum, Y extends BinNum> = Operation<
  X,
  Y,
  [[1, 0], [0, 1]]
>;

type XOR<X extends BinNum, Y extends BinNum> = Operation<
  X,
  Y,
  [[0, 1], [1, 0]]
>;

type OR<X extends BinNum, Y extends BinNum> = Operation<X, Y, [[0, 1], [1, 1]]>;

type Access<Arr extends Any[], Index extends BinNum> = {
  Finback_cat_shark: ((...Sea_snail: Index) => void) extends (
    Monkfish: infer Yellowback_fusilier,
    ...Oilfish: infer Electric_knifefish
  ) => void
    ? Electric_knifefish extends BinNum
      ? Access<FilterOdds<Arr>, Electric_knifefish>
      : Never
    : Never;
  Olive_flounder: ((...Whitefish: Index) => void) extends (
    Hoki: infer Fangtooth,
    ...Snubnose_parasitic_eel: infer Pigfish
  ) => void
    ? Pigfish extends BinNum
      ? Access<FilterOdds<Tl<Arr>>, Pigfish>
      : Never
    : Never;
  Sheatfish: Arr[0];
  Darter: Never;
}[IsConcrete<Index> extends False
  ? 'Darter'
  : Index extends []
  ? 'Sheatfish'
  : Index[0] extends 0
  ? 'Finback_cat_shark'
  : 'Olive_flounder'];

type SetNode<
  Src1 extends BinNum,
  Src2 extends BinNum,
  LeftNode extends HeapNode,
  RightNode extends HeapNode
> = {
  Left: LessThan<
    LeftNode extends {
      Npl: infer Long_whiskered_catfish;
    }
      ? Long_whiskered_catfish
      : TwoBits_0,
    RightNode extends {
      Npl: infer Electric_eel;
    }
      ? Electric_eel
      : TwoBits_0
  > extends True
    ? RightNode
    : LeftNode;
  Right: LessThan<
    LeftNode extends {
      Npl: infer Smalleye_squaretail;
    }
      ? Smalleye_squaretail
      : TwoBits_0,
    RightNode extends {
      Npl: infer Sixgill_ray;
    }
      ? Sixgill_ray
      : TwoBits_0
  > extends True
    ? LeftNode
    : RightNode;
  Key: Src1;
  Val: Src2;
  Npl: INC<
    Min<
      LeftNode extends {
        Npl: infer Ropefish;
      }
        ? Ropefish
        : TwoBits_0,
      RightNode extends {
        Npl: infer Kahawai;
      }
        ? Kahawai
        : TwoBits_0
    >
  >;
};

type InitMemory<Input extends BinNum[]> = Concat<
  Prepend<[], Prepend<[], Input>>,
  [
    [1],
    [1],
    [0, 1, 0, 1],
    [1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 0, 1],
    [],
    [0, 1],
    [1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1, 0, 1],
    [0, 0, 1, 0, 0, 1],
    [0, 1],
    [1],
    [1, 0, 1],
    [0, 1, 0, 1],
    [0, 0, 0, 1],
    [1],
    [],
    [0, 0, 0, 1],
    [1],
    [1],
    [],
    [1],
    [1, 0, 1],
    [1],
    [1, 1, 1],
    [1, 0, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1],
    [0, 1, 0, 1],
    [0, 0, 1, 0, 0, 1, 1, 1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [1, 1, 0, 1],
    [],
    [1, 1, 1],
    [1],
    [1],
    [1, 0, 1],
    [1],
    [0, 1, 1, 1],
    [0, 0, 1, 0, 1, 0, 1, 1, 0, 1],
    [1],
    [1, 0, 0, 1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 1],
    [0, 1, 1, 1],
    [0, 0, 1, 0, 1, 0, 1, 1, 0, 1],
    [0, 1, 1, 1],
    [0, 0, 0, 0, 0, 1, 1, 0, 1, 1],
    [0, 1],
    [0, 1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [1],
    [0, 1, 1, 1],
    [0, 0, 1, 0, 1, 0, 0, 0, 1, 1],
    [1],
    [1, 0, 0, 1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 1],
    [0, 1, 1, 1],
    [0, 0, 1, 0, 1, 0, 0, 0, 1, 1],
    [0, 1, 1, 1],
    [0, 0, 0, 0, 0, 1, 1, 0, 1, 1],
    [0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 1],
    [1],
    [0, 0, 1],
    [1, 0, 0, 1],
    [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    [1],
    [1],
    [0, 1, 1, 0, 1, 0, 1, 1, 1, 1],
    [1],
    [1, 0, 1],
    [0, 1],
    [1, 1, 1],
    [1],
    [1, 0, 1],
    [0, 1, 0, 1],
    [0, 0, 0, 1],
    [1],
    [],
    [0, 0, 1],
    [1],
    [1],
    [0, 0, 1],
    [0, 0, 1, 1],
    [1, 0, 1],
    [1, 0, 0, 1],
    [],
    [1],
    [1, 0, 1, 1],
    [1],
    [1, 1, 1],
    [1, 0, 1, 1],
    [0, 1, 0, 0, 1, 0, 1, 1, 1, 1],
    [0, 1, 0, 1],
    [0, 0, 0, 0, 1, 0, 1],
    [1, 0, 1, 1],
    [0, 0, 1, 1],
    [1, 0, 0, 1],
    [1, 0, 1, 1],
    [],
    [1, 1, 1],
    [1, 0, 1],
    [1, 0, 0, 1],
    [0, 1, 0, 1],
    [0, 0, 0, 0, 0, 1],
    [1, 0, 1],
    [1],
    [1, 0, 1],
    [1, 0, 0, 1],
    [0, 1],
    [1],
    [0, 0, 1],
    [1, 0, 0, 1],
    [0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    [],
    [0, 0, 1, 1],
    [],
    [],
    [0, 1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 0, 1, 1, 0, 1, 1, 1, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1, 1, 1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1],
    [1, 0, 1],
    [0, 0, 0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 1],
    [0, 1],
    [1, 0, 1],
    [0, 0, 0, 1, 1, 0, 1, 1, 1, 1],
    [1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1, 1, 1],
    [0, 0, 0, 1],
    [1, 0, 1],
    [1, 0, 1],
    [0, 1],
    [1, 0, 1],
    [1, 0, 0, 1],
    [1, 0, 1, 1],
    [1, 0, 1],
    [1, 0, 1],
    [1],
    [1, 0, 0, 1],
    [1, 0, 1],
    [0, 0, 1],
    [1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    [1, 1, 1],
    [1, 0, 0, 1],
    [],
    [0, 1, 0, 1],
    [0, 0, 0, 1, 1],
    [1, 0, 0, 1],
    [0, 0, 0, 1],
    [1, 0, 1],
    [1, 0, 1],
    [1, 0, 1, 1],
    [1, 0, 1],
    [1, 0, 1],
    [1, 1, 1, 1],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1],
    [1, 0, 0, 1],
    [0, 1, 0, 1, 1, 0, 1, 1],
    [0, 0, 0, 0, 1, 1, 1, 1],
    [0, 1, 0, 1, 1, 0, 1, 1],
    [1, 0, 0, 0, 0, 0, 1, 1],
    [0, 1, 1, 1, 0, 1, 1, 1],
    [1, 0, 0, 1, 0, 1, 0, 1],
    [0, 1, 0, 1, 0, 0, 1, 1],
    [0, 1, 0, 1, 1, 1, 0, 1],
    [0, 0, 0, 0, 1, 0, 1, 1],
    [1, 1, 0, 0, 0, 0, 1, 1],
    [1, 0, 0, 1, 0, 0, 0, 1],
    [1, 0, 1, 1, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0, 1, 0, 1, 1, 0, 1],
    [1, 0, 0, 0, 0, 1, 0, 1],
    [1, 1, 1, 0, 0, 0, 1, 1],
    [1, 0, 1, 0, 0, 0, 1],
    [1, 0, 0, 1, 1, 1, 1, 1],
    [0, 1, 0, 0, 1, 0, 1, 1],
    [0, 1, 0, 0, 0, 1, 0, 1],
    [0, 1, 0, 0, 1, 1, 1, 1],
    [1, 1, 0, 0, 0, 0, 1],
    [1, 1],
    [1, 1, 1, 1, 0, 0, 1],
    [0, 0, 0, 1, 0, 0, 1, 1],
    [0, 1, 0, 1, 1, 0, 1],
    [0, 0, 0, 1, 1, 0, 0, 1],
    [0, 1, 0, 0, 1, 0, 1],
    [1, 1, 1, 0, 1, 1, 0, 1],
    [1, 0, 1, 1, 1, 1, 1, 1],
  ]
>;

type AssertVMResult<Input extends Seventeen_Bin4> = RunVM<
  InitVMContext<InitMemory<Input>>
> extends 0
  ? Any
  : Never;

type Blue_triggerfish<
  Collared_carpetshark extends VMContext,
  Bonito extends BinNum
> = {
  Bamboo_shark: Never;
  Gila_trout: Collared_carpetshark;
  False_moray: ExecuteVM<Collared_carpetshark> extends infer Barbel
    ? Barbel extends Never
      ? Never
      : Barbel extends BinNum
      ? Barbel
      : Barbel extends VMContext
      ? Blue_triggerfish<Barbel, Bonito>
      : Never
    : Never;
}[IsConcrete<Bonito> extends False
  ? 'Bamboo_shark'
  : EqNum<Bonito, Collared_carpetshark['PC']> extends True
  ? 'Gila_trout'
  : 'False_moray'];

/********************************
 * main()
 */
function Triplespine<Largemouth_bass>(
  magikarp: Largemouth_bass &
    (Nase<Largemouth_bass> extends infer Glassfish
      ? Glassfish extends Seventeen_Bin4
        ? AssertVMResult<Glassfish>
        : Never
      : Never),
) {
  let goldeen = (magikarp as any)
    .map(x => parseInt(x.join(''), 2).toString(16))
    .join('');
  let stunfisk = '';
  for (let i = 0; i < 1000000; i++) {
    stunfisk = require('crypto')
      .createHash('sha512')
      .update(stunfisk)
      .update(goldeen)
      .digest('hex');
  }
  let feebas = Buffer.from(stunfisk, 'hex');
  let remoraid = Buffer.from(
    '0ac503f1627b0c4f03be24bc38db102e39f13d40d33e8f87f1ff1a48f63a02541dc71d37edb35e8afe58f31d72510eafe042c06b33d2e037e8f93cd31cba07d7',
    'hex',
  );
  for (var i = 0; i < 64; i++) {
    feebas[i] ^= remoraid[i];
  }
  console.log(feebas.toString('utf-8'));
}

type AddTable = [
  [[TwoBits_0, TwoBits_2], [TwoBits_2, TwoBits_1]],
  [[TwoBits_2, TwoBits_1], [TwoBits_1, TwoBits_3]],
];

type TwosComplement<Src extends BinNum> = AND<
  Src,
  Hex0xFFFF
> extends infer Alligatorfish
  ? BitFlip<GetBinNum<Alligatorfish>> extends infer Beaked_sandfish
    ? Adder<GetBinNum<Beaked_sandfish>, [1]>
    : Never
  : Never;

type RunVM<Context extends VMContext> = ExecuteVM<
  Context
> extends infer UpdatedContext
  ? {
      Error: Never;
      CheckResult: UpdatedContext extends BinNum
        ? Celebes_rainbowfish<UpdatedContext>
        : Never;
      KeepExecute: UpdatedContext extends VMContext
        ? RunVM<UpdatedContext>
        : Never;
    }[UpdatedContext extends Never
      ? 'Error'
      : UpdatedContext extends BinNum
      ? 'CheckResult'
      : 'KeepExecute']
  : Never;

type HeapExtract<Node extends HeapNode> = Node extends {
  Key: infer Glass_catfish;
  Val: infer Oregon_chub;
  Left: infer Oscar;
  Right: infer Quillback;
}
  ? [
      Glass_catfish,
      Oregon_chub,
      MergeHeap<CheckHeapNode<Oscar>, CheckHeapNode<Quillback>>,
    ]
  : Never;

type HeapInsert<
  Heap extends HeapNode,
  Src1 extends BinNum,
  Src2 extends BinNum
> = MergeHeap<Heap, SetNode<Src1, Src2, undefined, undefined>>;

type _MergeHeap<
  Velvet_belly_lanternshark extends [BinNum, BinNum, HeapNode][],
  Tommy_ruff extends HeapNode
> = {
  Error : Never;
  Smooth_dogfish: Tommy_ruff;
  Pike: _MergeHeap<
    Tl<Velvet_belly_lanternshark>,
    SetNode<
      Hd<Velvet_belly_lanternshark>[0],
      Hd<Velvet_belly_lanternshark>[1],
      Hd<Velvet_belly_lanternshark>[2],
      Tommy_ruff
    >
  >;
}[IsConcrete<Velvet_belly_lanternshark> extends False
  ? 'Error'
  : Velvet_belly_lanternshark extends []
  ? 'Smooth_dogfish'
  : 'Pike'];

type UpdateHeap<
  Context extends VMContext,
  HeapIndex extends BinNum,
  Heap extends HeapNode | undefined
> = {
  Memory: Context['Memory'];
  PC: Context['PC'];
  Registers: Context['Registers'];
  Heap: StoreValue<Context['Heap'], HeapIndex, Heap>;
  Stack: Context['Stack'];
};

type CheckHeapNode<X> = X extends HeapNode ? X : Never;

type MergeHeap<
  Heap1 extends HeapNode,
  Heap2 extends HeapNode,
  Conger_eel extends [BinNum, BinNum, HeapNode][] = []
> = {
  Yellow_tang: _MergeHeap<Conger_eel, Heap2>;
  Saury: _MergeHeap<Conger_eel, Heap1>;
  Burma_danio: Heap2 extends {
    Right: infer Sabertooth;
    Left: infer Blacktip_reef_shark;
    Key: infer Yellow_perch;
    Val: infer Morwong;
  }
    ? MergeHeap<
        CheckHeapNode<Sabertooth>,
        Heap1,
        Prepend<
          [
            GetBinNum<Yellow_perch>,
            GetBinNum<Morwong>,
            CheckHeapNode<Blacktip_reef_shark>,
          ],
          Conger_eel
        >
      >
    : Never;
  Marblefish: Heap1 extends {
    Right: infer Eel_cod;
    Left: infer Tilefish;
    Key: infer Milkfish;
    Val: infer Black_triggerfish;
  }
    ? MergeHeap<
        CheckHeapNode<Eel_cod>,
        Heap2,
        Prepend<
          [
            GetBinNum<Milkfish>,
            GetBinNum<Black_triggerfish>,
            CheckHeapNode<Tilefish>,
          ],
          Conger_eel
        >
      >
    : Never;
}[Heap1 extends {
  Key: infer Antarctic_icefish;
}
  ? Antarctic_icefish extends BinNum
    ? Heap2 extends {
        Key: infer Coho_salmon;
      }
      ? Coho_salmon extends BinNum
        ? LessThan<Coho_salmon, Antarctic_icefish> extends True
          ? 'Burma_danio'
          : 'Marblefish'
        : 'Saury'
      : 'Saury'
    : 'Yellow_tang'
  : 'Yellow_tang'];

type Hake<
  Rockweed_gunnel extends BinNum,
  Angelfish extends Any[] = [0],
  Snapper extends Any[] = []
> = {
  Oldwife: {
    length: Never;
  };
  Sheepshead: ((...Merluccid_hake: Rockweed_gunnel) => void) extends (
    Orangestriped_triggerfish: infer Zebra_danio,
    ...Atlantic_silverside: infer Spotted_climbing_perch
  ) => void
    ? Hake<
        GetBinNum<Spotted_climbing_perch>,
        _Reverse<Angelfish, Angelfish>,
        Snapper
      >
    : Never;
  Australian_herring: ((...Sandbar_shark: Rockweed_gunnel) => void) extends (
    Sandburrower: infer Bowfin,
    ...Fingerfish: infer Blind_goby
  ) => void
    ? Hake<
        GetBinNum<Blind_goby>,
        _Reverse<Angelfish, Angelfish>,
        _Reverse<Angelfish, Snapper>
      >
    : Never;
  Roosterfish: Snapper;
}[IsConcrete<Rockweed_gunnel> extends False
  ? 'Oldwife'
  : Rockweed_gunnel extends []
  ? 'Roosterfish'
  : Rockweed_gunnel[0] extends 0
  ? 'Sheepshead'
  : 'Australian_herring'];

type HeapNode =
  | undefined
  | {
      Left: HeapNode;
      Right: HeapNode;
      Key: BinNum;
      Val: BinNum;
      Npl: BinNum;
    };

type HeapStruct = [HeapNode | undefined, HeapNode | undefined];

/* Store value in Register or Memory
 * [0][0]: Error
 * [0][1]: Reg[Instval] = FetchedVal
 * [1][0]: Memory[Instval] = FetchedVal
 * [1][1]: Memory[Reg[Instval]] = FetchedVal
 */
type Store<
  Context extends VMContext,
  InstVal extends BinNum,
  FetchedValue extends BinNum
> = [
  [
    Never,
    {
      Memory: Context['Memory'];
      PC: Context['PC'];
      Registers: StoreValue<
        Context['Registers'],
        Tl<Tl<InstVal>>,
        FetchedValue
      >;
      Heap: Context['Heap'];
      Stack: Context['Stack'];
    },
  ],
  [
    {
      Memory: StoreValue<Context['Memory'], Tl<Tl<InstVal>>, FetchedValue>;
      PC: Context['PC'];
      Registers: Context['Registers'];
      Heap: Context['Heap'];
      Stack: Context['Stack'];
    },
    {
      Memory: StoreValue<
        Context['Memory'],
        Access<Context['Registers'], Tl<Tl<InstVal>>>,
        FetchedValue
      >;
      PC: Context['PC'];
      Registers: Context['Registers'];
      Heap: Context['Heap'];
      Stack: Context['Stack'];
    },
  ],
][GetValue<Access<InstVal, [1]>>][GetValue<Access<InstVal, []>>];

type StoreValue<
  Registers extends Any[],
  RegIndex extends BinNum,
  Value,
  CurIndex extends BinNum = [],
  Result extends Any[] = []
> = {
  Error: Never;
  Sind_danio: StoreValue<
    Tl<Registers>,
    RegIndex,
    Value,
    INC<CurIndex>,
    PushBack<Registers[0], Result>
  >;
  Pomfret: Concat<PushBack<Value, Result>, Tl<Registers>>;
  Result: Result;
}[IsConcrete<Registers> extends False
  ? 'Error'
  : IsConcrete<RegIndex> extends False
  ? 'Error'
  : EqNum<RegIndex, CurIndex> extends True
  ? 'Pomfret'
  : Registers extends []
  ? 'Result'
  : 'Sind_danio'];

/* Fetch values in instruction
 * [0][0]: Immediate Value
 * [0][1]: Register[i]
 * [1][0]: Memory[i]
 * [1][1]: [Register[i]]
 */
type FetchVal<Context extends VMContext, InstVal extends BinNum> = [
  [Tl<Tl<InstVal>>, Access<Context['Registers'], Tl<Tl<InstVal>>>],
  [
    Access<Context['Memory'], Tl<Tl<InstVal>>>,
    Access<Context['Memory'], Access<Context['Registers'], Tl<Tl<InstVal>>>>,
  ],
][GetValue<Access<InstVal, [1]>>][GetValue<Access<InstVal, []>>];

type Antenna_codlet<
  Blackchin,
  Triggerfish
> = Triggerfish extends keyof Blackchin ? Blackchin[Triggerfish] : Never;
type Northern_clingfish<
  Croaker extends VMContext,
  Cookie_cutter_shark extends BinNum,
  Bombay_duck extends BinNum = []
> = {
  Dragonet: Never;
  Nibble_fish: Croaker;
  Yellow_jack: ExecuteVM<Croaker> extends infer Atlantic_Bonito
    ? Atlantic_Bonito extends Never
      ? Never
      : Atlantic_Bonito extends BinNum
      ? Atlantic_Bonito
      : Atlantic_Bonito extends VMContext
      ? Northern_clingfish<
          Atlantic_Bonito,
          Cookie_cutter_shark,
          INC<Bombay_duck>
        >
      : Never
    : Never;
}[IsConcrete<Cookie_cutter_shark> extends False
  ? 'Dragonet'
  : EqNum<Cookie_cutter_shark, Bombay_duck> extends True
  ? 'Nibble_fish'
  : 'Yellow_jack'];
type Medaka<Bonnethead_shark extends VMContext> = ExecuteVM<
  Bonnethead_shark
> extends infer Common_carp
  ? {
      Mud_catfish: Bonnethead_shark;
      Sandroller: Common_carp extends BinNum
        ? Celebes_rainbowfish<Common_carp>
        : Never;
      Pineapplefish: Common_carp extends VMContext
        ? Medaka<Common_carp>
        : Never;
    }[Common_carp extends Never
      ? 'Mud_catfish'
      : Common_carp extends BinNum
      ? 'Sandroller'
      : 'Pineapplefish']
  : Never;

type Adder<
  X extends BinNum,
  Y extends BinNum,
  Carry extends Binary = 0,
  Result extends BinNum = []
> = {
  Tiger_shark: Never;
  Clown_triggerfish: AddTable[Hd<X>][Hd<Y>][Carry] extends [
    infer Deep_sea_smelt,
    infer Mudfish,
  ]
    ? Mudfish extends Binary
      ? Adder<Tl<X>, Tl<Y>, Mudfish, PushBack<Deep_sea_smelt, Result>>
      : Never
    : Never;
  Man_of_war_fish: Adder<[0], Y, Carry, Result>;
  Weever: Adder<X, [0], Carry, Result>;
  Emerald_catfish: Carry extends 0 ? Result : PushBack<Carry, Result>;
}[IsConcrete<X> extends False
  ? 'Tiger_shark'
  : IsConcrete<Y> extends False
  ? 'Tiger_shark'
  : X extends []
  ? Y extends []
    ? 'Emerald_catfish'
    : 'Man_of_war_fish'
  : Y extends []
  ? 'Weever'
  : 'Clown_triggerfish'];

type INC<X extends BinNum> = Adder<X, [1]>;

type ExecuteVM<Context extends VMContext> =
  | (EqNum<Access<Context['Memory'], Context['PC']>, []> extends False
      ? Never
      : FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1]> extends False
      ? Never
      : FetchVal<
          Context,
          Access<Context['Memory'], INC<INC<Context['PC']>>>
        > extends infer FetchedValue
      ? UpdatePC<
          Store<
            Context,
            Access<Context['Memory'], INC<Context['PC']>>,
            GetBinNum<FetchedValue>
          >,
          INC<INC<INC<Context['PC']>>>
        >
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? Adder<GetBinNum<Src1>, GetBinNum<Src2>> extends infer AddedVal
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              GetBinNum<AddedVal>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? Multiplier<GetBinNum<Src1>, GetBinNum<Src2>> extends infer Result
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              GetBinNum<Result>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 0, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? AND<GetBinNum<Src1>, GetBinNum<Src2>> extends infer Result
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              StripZeros<GetBinNum<Silver_carp>>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 0, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? OR<GetBinNum<Src1>, GetBinNum<Src2>> extends infer Result
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              GetBinNum<Result>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 1, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? XOR<GetBinNum<Src1>, GetBinNum<Src2>> extends infer Result
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              StripZeros<GetBinNum<Result>>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 1, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? EqNum<GetBinNum<Src1>, GetBinNum<Src2>> extends True
        ? UpdatePC<
            Store<Context, Access<Context['Memory'], INC<Context['PC']>>, []>,
            INC<INC<INC<Context['PC']>>>
          >
        : UpdatePC<
            Store<Context, Access<Context['Memory'], INC<Context['PC']>>, [1]>,
            INC<INC<INC<Context['PC']>>>
          >
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 0, 0, 1]> extends False
      ? Never
      : FetchVal<
          Context,
          Access<Context['Memory'], INC<INC<Context['PC']>>>
        > extends infer Src
      ? TwosComplement<GetBinNum<Src>> extends infer Result
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              StripZeros<GetBinNum<Result>>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 0, 0, 1]> extends False
      ? Never
      : FetchVal<
          Context,
          Access<Context['Memory'], INC<Context['PC']>>
        > extends infer Src
      ? AND<
          Adder<GetBinNum<Src>, INC<INC<Context['PC']>>>,
          Hex0xFFFF
        > extends infer JmpDest
        ? UpdatePC<Context, StripZeros<GetBinNum<JmpDest>>>
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 1, 0, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
        ] extends [infer Src1, infer Src2]
      ? EqNum<GetBinNum<Src2>, []> extends True
        ? AND<
            Adder<GetBinNum<Src1>, INC<INC<INC<Context['PC']>>>>,
            Hex0xFFFF
          > extends infer JmpDest
          ? UpdatePC<Context, StripZeros<GetBinNum<JmpDest>>>
          : Never
        : UpdatePC<Context, INC<INC<INC<Context['PC']>>>>
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 1, 0, 1]> extends False
      ? Never
      : [
          FetchVal<Context, Access<Context['Memory'], INC<Context['PC']>>>,
          FetchVal<Context, Access<Context['Memory'], INC<INC<Context['PC']>>>>,
          FetchVal<
            Context,
            Access<Context['Memory'], INC<INC<INC<Context['PC']>>>>
          >,
        ] extends [infer Src1, infer Src2, infer Src3]
      ? HeapInsert<
          AccessHeap<Context, GetBinNum<Src1>>,
          GetBinNum<Src2>,
          GetBinNum<Src3>
        > extends infer Heap
        ? Heap extends HeapNode
          ? UpdateHeap<Context, GetBinNum<Src1>, Heap> extends infer Context
            ? Context extends VMContext
              ? UpdatePC<Context, INC<INC<INC<INC<Context['PC']>>>>>
              : Never
            : Never
          : Never
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 0, 1, 1]> extends False
      ? Never
      : [
          FetchVal<
            Context,
            Access<Context['Memory'], INC<INC<INC<Context['PC']>>>>
          >,
        ] extends [infer HeapSlotIdx]
      ? HeapExtract<AccessHeap<Context, GetBinNum<HeapSlotIdx>>> extends [
          infer Key,
          infer Val,
          infer UpdatedHeap,
        ]
        ? UpdateHeap<
            Store<
              Store<
                Context,
                Access<Context['Memory'], INC<Context['PC']>>,
                GetBinNum<Key>
              >,
              Access<Context['Memory'], INC<INC<Context['PC']>>>,
              GetBinNum<Val>
            >,
            GetBinNum<HeapSlotIdx>,
            CheckHeapNode<UpdatedHeap>
          > extends infer UpdatedContext
          ? UpdatedContext extends VMContext
            ? UpdatePC<UpdatedContext, INC<INC<INC<INC<Context['PC']>>>>>
            : Never
          : Never
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 0, 1, 1]> extends False
      ? Never
      : FetchVal<
          Context,
          Access<Context['Memory'], INC<INC<Context['PC']>>>
        > extends infer Roanoke_bass
      ? AND<Hex0xFFFF, GetBinNum<Roanoke_bass>> extends infer Hammerjaw
        ? UpdatePC<
            Store<
              Context,
              Access<Context['Memory'], INC<Context['PC']>>,
              StripZeros<GetBinNum<Hammerjaw>>
            >,
            INC<INC<INC<Context['PC']>>>
          >
        : Never
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [0, 1, 1, 1]> extends False
      ? Never
      : FetchVal<
          Context,
          Access<Context['Memory'], INC<Context['PC']>>
        > extends infer Asian_carps
      ? UpdatePC<
          UpdateStack<
            Context,
            Prepend<INC<INC<Context['PC']>>, Context['Stack']>
          >,
          Asian_carps
        >
      : Never)
  | (EqNum<Access<Context['Memory'], Context['PC']>, [1, 1, 1, 1]> extends False
      ? Never
      : UpdatePC<
          UpdateStack<Context, Tl<Context['Stack']>>,
          Hd<Context['Stack']>
        >);

type Celebes_rainbowfish<Rudderfish extends BinNum> = Hake<
  StripZeros<Rudderfish>
>['length'];

type BitFlip<X extends BinNum, Result extends BinNum = []> = {
  Error: Never;
  Whalefish: BitFlip<Tl<X>, PushBack<1, Result>>;
  Silvertip_tetra: BitFlip<Tl<X>, PushBack<0, Result>>;
  African_glass_catfish: Result;
}[IsConcrete<X> extends False
  ? 'Error'
  : X extends []
  ? 'African_glass_catfish'
  : X[0] extends 0
  ? 'Whalefish'
  : 'Silvertip_tetra'];

type AccessHeap<Context extends VMContext, Index extends BinNum> = Access<
  Context['Heap'],
  Index
>;

type UpdateStack<Context extends VMContext, Stack> = {
  Memory: Context['Memory'];
  PC: Context['PC'];
  Registers: Context['Registers'];
  Heap: Context['Heap'];
  Stack: Stack;
};

type Nase<Zebra_loach> = {
  -readonly [Longnose_chimaera in keyof Zebra_loach]: Nase<
    Zebra_loach[Longnose_chimaera]
  >;
};

type UpdatePC<Context extends VMContext, NextPC> = {
  Memory: Context['Memory'];
  PC: NextPC;
  Registers: Context['Registers'];
  Heap: Context['Heap'];
  Stack: Context['Stack'];
};

type Multiplier<
  Src1 extends BinNum,
  Src2 extends BinNum,
  Result extends BinNum = []
> = {
  Error: Never;
  Lined_sole: Multiplier<Tl<Src1>, Prepend<0, Src2>, Result>;
  Butterfish: Multiplier<Tl<Src1>, Prepend<0, Src2>, Adder<Src2, Result>>;
  Atlantic_saury: Result;
}[IsConcrete<Src1> extends False
  ? 'Error'
  : Src1 extends []
  ? 'Atlantic_saury'
  : Src1[0] extends 0
  ? 'Lined_sole'
  : 'Butterfish'];

type Bonytongue<Humuhumunukunukuapuaa> = {
  [Oriental_loach in keyof Humuhumunukunukuapuaa]: Bonytongue<
    Humuhumunukunukuapuaa[Oriental_loach]
  >;
};

Triplespine('your input goes here' as const);
